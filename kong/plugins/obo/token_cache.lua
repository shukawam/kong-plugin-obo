-- 交換済みトークンのキャッシュ
-- リクエストのたびに Entra ID へ交換リクエストを送るとレイテンシーとレート制限の問題が
-- 出るため、受信トークン（のハッシュ）をキーに交換済みトークンを kong.cache に保持する。
-- TTL は交換レスポンスの expires_in から余裕幅（cache_ttl_margin）を引いた値。

local resty_sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex

local M = {}

-- kong.cache（実体は lua-resty-mlcache）は既定で、期限切れ（stale）になった値を
-- 「IdP への再交換（exchange_fn）が失敗した」場合に resurrect_ttl 秒（Kong の既定は 30 秒。
-- kong/cache/init.lua 参照）だけそのまま復活させ、呼び出し元にはエラーを返さずに
-- 古い値をそのまま渡してしまう。これは「短寿命トークンや小さい cache_ttl_margin の構成で、
-- TTL 切れ直後にたまたま IdP 呼び出しが失敗すると、期限切れの token B が最大 30 秒間、
-- 別リクエスト（並行ワーカー）に対して upstream へ送られ続ける」という問題を引き起こす
-- （GitHub Issue #7）。
--
-- 対策として resurrect_ttl を「実質的に無効化」したいが、そのまま 0 を渡すのは危険。
-- Lua では 0 は truthy（false/nil だけが falsy）であるため、mlcache 内部の resurrect を
-- スキップする判定 `if not went_stale or not resurrect_ttl`（値が stale でないか、
-- resurrect_ttl が未指定かの論理和）のうち `not resurrect_ttl` 側は 0 を「無効」と
-- 見なしてくれず、stale 時には resurrect 処理自体は実行されてしまう。その上 mlcache は「TTL(この場合は resurrect_ttl) が 0」を
-- 「無期限（決して失効しない）」という別の意味で特別扱いするため、resurrect_ttl=0 を渡すと
-- 一度 resurrect された stale 値がその後ずっと（ワーカーが再起動するまで）居座ってしまう、
-- という既定の 30 秒より遥かに悪い結果になる（実 mlcache で動作検証済み）。
-- Kong 本体の key-auth プラグイン（kong/plugins/key-auth/handler.lua）が同じ理由から
-- resurrect_ttl に 0 ではなく極小の正の値 0.001 を使っているのに倣い、ここでも同じ値を使う。
local RESURRECT_TTL = 0.001

-- expires_in の上限（秒）。24 時間。
-- IdP の異常応答で極端に大きい値（あるいは巨大な有限値）が返っても、
-- 交換済みトークンが実質的に「ずっと消えないキャッシュ」にならないようにするための安全弁
local MAX_EXPIRES_IN = 86400

-- Entra からの expires_in を TTL 計算に使える安全な数値へ正規化するローカル関数
-- 数値として解釈できない値（文字列以外の型・数値化できない文字列・欠落=nil）や
-- NaN・無限大・負数は 0 として扱う（呼び出し元の math.max により下限 1 秒に落ちる = fail safe）。
-- 有限の正の数値でも MAX_EXPIRES_IN を超える場合は上限にクランプする。
-- @param expires_in 交換レスポンスの expires_in フィールド（型不定）
-- @return 0 以上 MAX_EXPIRES_IN 以下の数値
local function normalize_expires_in(expires_in)
  local n = tonumber(expires_in)

  -- tonumber が nil を返すのは「数値化できない文字列」「nil（欠落）」「テーブル等の非対応型」の場合
  if n == nil then
    return 0
  end

  -- NaN は IEEE754 の仕様上、自分自身と比較しても等しくならない（n ~= n が真になる）
  -- この性質を利用して NaN 判定する（Lua には isnan のような専用関数がない）
  if n ~= n then
    return 0
  end

  -- 無限大（math.huge / -math.huge）や負数は異常値として 0 扱いにする
  if n == math.huge or n == -math.huge or n < 0 then
    return 0
  end

  -- 上限クランプ: 異常に大きい有限値で長期キャッシュ化しないようにする
  if n > MAX_EXPIRES_IN then
    return MAX_EXPIRES_IN
  end

  return n
end

-- SHA-256 の 16 進ダイジェストを返すローカル関数
local function sha256_hex(s)
  local digest = resty_sha256:new()
  digest:update(s)
  return to_hex(digest:final())
end

-- キャッシュキーを作るローカル関数
-- 生のトークンをキーにしない（共有メモリに平文トークンを並べないため）。
-- client_id と scopes に加えてテナント（tenant_id / identity_base_url）もキーに含め、
-- 同一トークン・client_id・scopes でもテナントが異なれば別キャッシュになるようにする
-- （テナントをまたいだ交換済みトークンの誤ヒットを防ぐ）。
-- ssl_verify もキーに含める理由: ssl_verify=false（TLS 検証なし）の設定で交換・
-- キャッシュされた token B（MITM 下では任意の値になり得る）を、同一テナント・
-- client_id・scopes の ssl_verify=true（検証あり）設定が再利用してしまう越境を防ぐ
-- （jwt_validator.lua の JWKS キャッシュキーと同じ方針。外部レビュー指摘）
local function cache_key(conf, incoming_token)
  local material = incoming_token .. "|" .. conf.client_id .. "|" .. table.concat(conf.scopes, " ")
      .. "|" .. tostring(conf.tenant_id) .. "|" .. tostring(conf.identity_base_url)
      .. "|" .. tostring(conf.ssl_verify == true)
  return "obo:token:" .. sha256_hex(material)
end

-- 交換済みトークンを取得する。キャッシュミス時のみ exchange_fn を呼ぶ
-- @param conf プラグイン設定
-- @param incoming_token 受信アクセストークン（キャッシュキーの材料）
-- @param exchange_fn 引数なしで (res, err) を返す関数（token_exchange.exchange と同じ契約）
-- @return 交換後アクセストークン文字列。失敗時は nil と exchange_fn のエラー
function M.get(conf, incoming_token, exchange_fn)
  -- キャッシュ無効時は素通しで毎回交換する
  if not conf.token_cache_enabled then
    local res, err = exchange_fn()
    if not res then
      return nil, err
    end
    return res.access_token
  end

  -- コールバック内で起きたエラーの詳細（テーブル）を持ち出すための変数。
  -- kong.cache のエラー伝搬は文字列化される可能性があるため、この方式で確実に取り出す
  local exchange_err

  -- 第 2 引数（opts）に resurrect_ttl を明示指定する。理由は RESURRECT_TTL の定義部コメント参照
  local token, cache_err, hit_lvl = kong.cache:get(
    cache_key(conf, incoming_token), { resurrect_ttl = RESURRECT_TTL }, function()
    local res, err = exchange_fn()
    if not res then
      exchange_err = err
      -- (nil, err) を返すとキャッシュされずにエラーが伝搬する（負キャッシュを防ぐ）
      return nil, "exchange failed"
    end
    -- 第 3 戻り値が TTL になる（mlcache の仕様）。期限切れ間際を避けるため margin を引く
    -- expires_in は IdP からの値をそのまま信用せず、正規化・上限クランプしてから使う
    local ttl = math.max(normalize_expires_in(res.expires_in) - conf.cache_ttl_margin, 1)
    return res.access_token, nil, ttl
  end)

  if exchange_err then
    return nil, exchange_err
  end

  -- hit_lvl == 4 は「stale（期限切れ）値が resurrect された」ことを示す mlcache の契約。
  -- resurrect_ttl を極小値にしていても、その一瞬の間に別ワーカーがこの resurrect された
  -- 値を拾ってしまう可能性はゼロではない（このワーカー自身の exchange_fn は一度も
  -- 呼ばれていないため exchange_err は立たない）。ここで明示的に失敗として扱うことで、
  -- 期限切れの token B を絶対に upstream へ送らせないようにする
  if hit_lvl == 4 then
    kong.log.debug("obo: stale token was resurrected by kong.cache; treating as exchange failure")
    return nil, { status = 502, error = "idp_unreachable", detail = "stale token resurrection suppressed" }
  end

  if not token then
    -- exchange 以外の失敗（キャッシュ層自体の異常）
    return nil, { status = 500, error = "cache_failure", detail = tostring(cache_err) }
  end
  return token
end

return M
