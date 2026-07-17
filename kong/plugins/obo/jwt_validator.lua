-- 受信アクセストークン（クライアントが送ってきた Bearer トークン）の検証
-- 仕様: docs/obo/05-token-validation.md
--   1. OpenID configuration（v2.0）から jwks_uri を取得（kong.cache でキャッシュ）
--   2. JWKS を取得し、トークンヘッダーの kid で公開鍵を選択
--      未知の kid は 1 回だけ再取得を試み、取得成功時のみキャッシュを置換（鍵ロールオーバー追従）
--   3. RS256 署名検証
--   4. クレーム検証: iss 完全一致 / aud 一致 / exp / nbf（クロックスキュー許容付き）

local pkey  = require "resty.openssl.pkey"
local http  = require "resty.http"
local cjson = require "cjson.safe"
local util  = require "kong.plugins.obo.util"

local M = {}

-- exp/nbf 検証で許容するクロックずれ（秒）
local CLOCK_SKEW = 60

-- OpenID 設定・JWKS のキャッシュ秒数。
-- 公式推奨の「鍵更新チェックは 24 時間ごとが妥当」より十分短くしてある（docs/obo/05）
local METADATA_TTL = 3600

-- 未知 kid による JWKS 再取得の頻度を制限するための、ワーカー単位の最終再取得時刻
-- （認証不要リクエストでキャッシュ無効化を連打される DoS を防ぐ。docs/obo/05 の
--   「未知 kid は再取得」という挙動自体は維持し、頻度だけを制限する）
local JWKS_REFETCH_INTERVAL = 30  -- 秒
local last_refetch = {}  -- jwks_cache_key -> ngx.time() of last refetch

-- 直近の再取得が upstream 起因（IdP 到達不能・応答異常・キャッシュ層異常）で失敗したかを
-- キー単位で覚えておくワーカーローカルのフラグ（Medium 2 対応）。
-- 抑止期間中に来た未知 kid を「トークン不正（401）」と「IdP 障害の継続（502）」の
-- どちらに分類するかの判断に使う。直前の再取得が失敗していれば障害継続とみなす
local last_refetch_failed = {}  -- jwks_cache_key -> true（直近の再取得が失敗）

-- JWK(JSON文字列) → pkey オブジェクトのワーカーローカルなメモ化。
-- JWKS キャッシュは shm 越しに共有するため JWK を JSON 文字列で保持しており（正しい設計）、
-- その結果リクエストごとに pkey.new(JWK) で RSA 公開鍵をパースし直していた（実測 ~3.9us/req）。
-- 同一 JWK に対する pkey オブジェクトをここにメモ化して再パースを避ける。
-- キーは JWK JSON 文字列そのもの（内容アドレス方式）。鍵ロールオーバーで JWK が変われば
-- 必ず別キーになるため、古い pkey が誤って使われることはない（stale 参照が起きない）。
-- なお、ここに格納されるのは IdP が実際に配布した正常な鍵のみ（未知の kid は
-- get_signing_key が nil を返すためここに到達せず、壊れた JWK はパース失敗で格納されない）。
-- 上限は、多テナント設定や長期の鍵ローテーションでエントリが累積することへの保険である。
-- 鍵はテナントあたり数個なので 32 で十分。超過時は丸ごと破棄する（再パースは安価なので許容）。
local PKEY_MEMO_MAX = 32
local pkey_memo = {}        -- jwk_json -> pkey オブジェクト
local pkey_memo_count = 0   -- pkey_memo のエントリ数（#t はハッシュ部を数えられないため自前で持つ）

-- JWK(JSON文字列) を pkey オブジェクトに変換するローカル関数（メモ化付き）
-- @return pkey, err。パース失敗時は nil とエラー理由
local function jwk_to_pkey(jwk_json)
  local cached = pkey_memo[jwk_json]
  if cached then
    return cached
  end
  local pk, err = pkey.new(jwk_json, { format = "JWK" })
  if not pk then
    return nil, err
  end
  -- 上限に達していたら丸ごとクリアしてから入れ直す（単純な有界化）
  if pkey_memo_count >= PKEY_MEMO_MAX then
    pkey_memo = {}
    pkey_memo_count = 0
  end
  pkey_memo[jwk_json] = pk
  pkey_memo_count = pkey_memo_count + 1
  return pk
end

-- JWT 文字列を分解して header / payload / signature を取り出すローカル関数
-- @return { header, payload, signature, signing_input } のテーブル。不正なら nil とエラー
local function decode_jwt(token)
  if type(token) ~= "string" then
    return nil, "token is not a string"
  end
  local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
  if not h then
    return nil, "malformed JWT: expected 3 dot-separated parts"
  end
  local header_json  = util.b64url_decode(h)
  local payload_json = util.b64url_decode(p)
  local signature    = util.b64url_decode(s)
  if not header_json or not payload_json or not signature then
    return nil, "malformed JWT: invalid base64url"
  end
  local header  = cjson.decode(header_json)
  local payload = cjson.decode(payload_json)
  if type(header) ~= "table" or type(payload) ~= "table" then
    return nil, "malformed JWT: invalid JSON"
  end
  return {
    header = header,
    payload = payload,
    signature = signature,
    -- 署名対象は「base64url(header).base64url(payload)」の文字列そのもの
    signing_input = h .. "." .. p,
  }
end

-- URL に GET して JSON をデコードして返すローカル関数
local function http_get_json(conf, url)
  local client = http.new()
  client:set_timeout(conf.http_timeout)
  local res, err = client:request_uri(url, {
    method = "GET",
    ssl_verify = conf.ssl_verify,
  })
  if not res then
    return nil, "request to " .. url .. " failed: " .. tostring(err)
  end
  if res.status ~= 200 then
    return nil, "unexpected status " .. res.status .. " from " .. url
  end
  local body = cjson.decode(res.body)
  if type(body) ~= "table" then
    return nil, "invalid JSON from " .. url
  end
  return body
end

-- OpenID configuration の取得元 authority を導出するローカル関数。
-- OIDC Discovery ではメタデータの issuer が、メタデータ取得に使った authority
-- （{identity_base_url}/{tenant_id}/v2.0）と完全一致しなければならない
local function metadata_authority(conf)
  return util.build_tenant_url(conf.identity_base_url, conf.tenant_id, "v2.0")
end

-- メタデータが自己申告した issuer を検証するローカル関数。
-- 検証を通った issuer が、受信トークンの iss クレームの「唯一の期待値」になる。
-- @return 検証済み issuer 文字列。問題があれば nil, エラー理由
local function validate_metadata_issuer(conf, issuer)
  if type(issuer) ~= "string" then
    return nil, "issuer missing in openid-configuration"
  end
  if util.is_guid(conf.tenant_id) then
    -- GUID テナント: OIDC Discovery のとおり issuer は取得元 authority
    -- （{identity_base_url}/{tenant_id}/v2.0）と完全一致すること。
    -- 不一致はメタデータの正当性が疑わしい（IdP 側の異常）ため取得失敗として扱う
    if issuer ~= metadata_authority(conf) then
      return nil, "openid-configuration issuer mismatch"
    end
  else
    -- ドメイン形式テナント（contoso.onmicrosoft.com 等）: Entra はドメイン名で
    -- メタデータを要求しても issuer を正規化済みの GUID 形式（{base}/{GUID}/v2.0）で
    -- 返す（実メタデータで裏取り済み）ため、取得元との完全一致は成立しない。
    -- 代わりに「identity_base_url と同一の scheme/authority」かつ
    -- 「パスが /{GUID}/v2.0 の形式」であることを検証する（docs/obo/05: v2.0 の
    -- テナント固有 issuer は https://login.microsoftonline.com/{tenantid}/v2.0 形式）
    local base_scheme, base_authority = util.url_scheme_authority(conf.identity_base_url)
    local iss_scheme, iss_authority = util.url_scheme_authority(issuer)
    if iss_scheme ~= base_scheme or iss_authority ~= base_authority then
      return nil, "openid-configuration issuer host mismatch"
    end
    -- authority の直後が「/{GUID}/v2.0」で終わる形式であることを確認する
    local tid = issuer:match("^%a[%w+.-]*://[^/]+/([^/]+)/v2%.0$")
    if not tid or not util.is_guid(tid) then
      return nil, "openid-configuration issuer is not a tenant-specific v2.0 issuer"
    end
  end
  -- conf.issuer はメタデータ issuer に対する任意の「ピン」（追加の防御）。
  -- 設定されている場合、メタデータの issuer がその値と完全一致しなければ拒否する。
  -- ※ 受信トークンの iss の期待値を別の値に置き換える用途には使えない
  --   （メタデータと矛盾する期待値は設定事故か IdP 異常のどちらかであるため fail-close する）
  if conf.issuer ~= nil and conf.issuer ~= issuer then
    return nil, "openid-configuration issuer does not match configured issuer"
  end
  return issuer
end

-- メタデータが返した jwks_uri の scheme と host を検証するローカル関数。
-- 別ホストや平文経路からの署名鍵取得を防ぐ（docs/obo/05: 鍵は jwks_uri から取得する前提）。
-- @return true。問題があれば nil, エラー理由
local function validate_jwks_uri(conf, jwks_uri)
  local base_scheme, base_authority = util.url_scheme_authority(conf.identity_base_url)
  local jwks_scheme, jwks_authority = util.url_scheme_authority(jwks_uri)
  if not jwks_scheme then
    return nil, "jwks_uri is not an absolute URL"
  end
  -- scheme: 原則 HTTPS を要求。identity_base_url が http のとき（統合テストのモック IdP 用）
  -- のみ http を許容する。本番は identity_base_url が https なので http は拒否される
  if jwks_scheme ~= "https" then
    if not (base_scheme == "http" and jwks_scheme == "http") then
      return nil, "jwks_uri must use https"
    end
  end
  -- host: identity_base_url と同一 authority（host[:port]）でなければならない
  if jwks_authority ~= base_authority then
    return nil, "jwks_uri host mismatch"
  end
  return true
end

-- v1.0 メタデータが自己申告した issuer を検証するローカル関数。
-- v1.0 の issuer は {scheme}://{host}/{GUID}/（末尾スラッシュ付き）形式で、実 Entra では
-- ホストが sts.windows.net になる（docs/obo/05）。ホストは identity_base_url と必ず異なるため
-- 同一 authority は要求せず、代わりに「パスのテナント GUID が検証済み v2.0 issuer の
-- テナント GUID と完全一致すること」を信頼の要にする（Entra の署名鍵は全テナント共通なので、
-- テナントの同定こそが issuer 検証の目的である）。
-- sts.windows.net はハードコードしない（ソブリンクラウド・モック IdP でホストが異なり得る）。
-- @param conf プラグイン設定
-- @param issuer v1.0 メタデータの issuer 値
-- @param tenant_guid 検証済み v2.0 issuer から取り出したテナント GUID
-- @return 検証済み v1.0 issuer 文字列。問題があれば nil, エラー理由
local function validate_v1_metadata_issuer(conf, issuer, tenant_guid)
  if type(issuer) ~= "string" then
    return nil, "issuer missing in v1.0 openid-configuration"
  end
  -- scheme: 原則 HTTPS を要求。identity_base_url が http のとき（統合テストのモック IdP 用）
  -- のみ http を許容する（validate_jwks_uri と同じ既存ルール）
  local base_scheme = util.url_scheme_authority(conf.identity_base_url)
  local iss_scheme = util.url_scheme_authority(issuer)
  if iss_scheme ~= "https" then
    if not (base_scheme == "http" and iss_scheme == "http") then
      return nil, "v1.0 issuer must use https"
    end
  end
  -- 形式: {scheme}://{host}/{GUID}/（末尾スラッシュ付き）であること
  local tid = issuer:match("^%a[%w+.-]*://[^/]+/([^/]+)/$")
  if not tid or not util.is_guid(tid) then
    return nil, "v1.0 issuer is not of the form {scheme}://{host}/{tenant GUID}/"
  end
  -- テナント GUID が v2.0 issuer と一致すること（ここが信頼の要）
  if tid ~= tenant_guid then
    return nil, "v1.0 issuer tenant does not match v2.0 issuer tenant"
  end
  return issuer
end

-- JWKS の鍵を kid で引けるように by_kid へ取り込むローカル関数。
-- pkey.new に渡せるよう JWK は JSON 文字列のまま保持する。
-- 署名鍵の issuer 検証（docs/obo/05 "Validate the signing key issuer"）:
-- Entra の JWKS は鍵エントリに issuer フィールドを含むことがある（実 JWKS で確認済み。
-- 多くは "{tenantid}" プレースホルダ入り、一部は具体的なテナント GUID）。
-- 存在する場合はプレースホルダを実テナントに置換した上で expected_issuer と
-- 完全一致しない鍵は取り込まない（他 issuer の鍵での署名検証を防ぐ）。
-- 既に by_kid にある kid は上書きしない（同一 JWKS 内で kid が重複した場合に、後から
-- 出てきた不正・破損した鍵に差し替わってしまうことを防ぐ保険）。
-- v1.0 / v2.0 の鍵は呼び出し側（load_metadata）が別々のマップに集めるため、
-- 「バージョン間で kid が衝突したときにどちらを優先するか」という概念自体がなくなっている
-- @param jwks_keys JWKS の keys 配列
-- @param expected_issuer この JWKS の鍵に期待する issuer（検証済みメタデータ issuer）
-- @param issuer_tenant {tenantid} プレースホルダの置換に使うテナント GUID
-- @param by_kid 取り込み先テーブル（kid → JWK JSON 文字列）。破壊的に更新される
local function collect_keys(jwks_keys, expected_issuer, issuer_tenant, by_kid)
  for _, jwk in ipairs(jwks_keys) do
    if type(jwk) == "table" and type(jwk.kid) == "string" and by_kid[jwk.kid] == nil then
      local key_issuer_ok = true
      if jwk.issuer ~= nil then
        if type(jwk.issuer) == "string" and issuer_tenant then
          -- gsub の第 4 引数 1 は「最初の 1 回だけ置換」。{tenantid} は Lua パターンの
          -- 特殊文字を含まないのでそのまま検索文字列に使える
          local resolved = jwk.issuer:gsub("{tenantid}", issuer_tenant, 1)
          key_issuer_ok = (resolved == expected_issuer)
        else
          key_issuer_ok = false
        end
      end
      if key_issuer_ok then
        by_kid[jwk.kid] = cjson.encode(jwk)
      end
    end
  end
end

-- OpenID 設定 → JWKS の順に取得し、検証済み issuer と kid → JWK(JSON文字列) の
-- テーブルをまとめて返すローカル関数。
-- allow_v1_tokens 有効時は v1.0 のメタデータ・JWKS も取得し、issuer_v1 と v1 の鍵を加える。
-- v1 側の取得・検証失敗はロード全体の失敗にする（fail-close。「v2 は通るが v1 は TTL まで
-- 失敗し続ける」という部分成功の曖昧な状態を作らない。v1/v2 は同一ホストなので障害は相関する）。
-- v1.0 / v2.0 の鍵は別々のマップ（keys_v2 / keys_v1）に集める。外部レビュー指摘（High）:
-- 以前は単一マップにマージしていたため、片方の JWKS にしか存在しない kid でも
-- 他方のバージョンのトークンを検証できてしまっていた。Microsoft の検証手順
-- （ver に対応するメタデータ文書で検証する。docs/obo/05）に合わせ、鍵セットを分離して
-- get_signing_key 側で「トークンの ver に対応する集合からしか選ばない」ようにする。
-- kong.cache のコールバックとして呼ばれる（キャッシュミス時のみ実行される）
-- @return { issuer = 検証済み v2.0 issuer, issuer_v1 = 検証済み v1.0 issuer または nil,
--           keys_v2 = { kid → JWK JSON 文字列 }, keys_v1 = 同上または nil（allow_v1_tokens
--           無効時）}。失敗時は nil, err
local function load_metadata(conf)
  -- v2.0 のメタデータ URL（docs/obo/05）。URL 連結は util.build_tenant_url に集約
  local config_url = util.build_tenant_url(conf.identity_base_url, conf.tenant_id,
      "v2.0/.well-known/openid-configuration")
  local oidc, err = http_get_json(conf, config_url)
  if not oidc then
    return nil, err
  end

  local issuer, iss_err = validate_metadata_issuer(conf, oidc.issuer)
  if not issuer then
    return nil, iss_err
  end

  if type(oidc.jwks_uri) ~= "string" then
    return nil, "jwks_uri missing in openid-configuration"
  end
  -- jwks_uri の scheme / host を検証（別ホスト・平文経路からの鍵取得を防ぐ）
  local ok_uri, uri_err = validate_jwks_uri(conf, oidc.jwks_uri)
  if not ok_uri then
    return nil, uri_err
  end

  local jwks, jwks_err = http_get_json(conf, oidc.jwks_uri)
  if not jwks then
    return nil, jwks_err
  end
  if type(jwks.keys) ~= "table" then
    return nil, "keys missing in JWKS"
  end

  -- issuer のパスからテナント ID（GUID）部分を取り出す
  -- （署名鍵の issuer 検証と、v1.0 メタデータ issuer 検証の両方で使う）
  local issuer_tenant = issuer:match("://[^/]+/([^/]+)/v2%.0$")

  local keys_v2 = {}
  collect_keys(jwks.keys, issuer, issuer_tenant, keys_v2)
  if next(keys_v2) == nil then
    -- 実 Entra が鍵 0 件の JWKS を配布することはなく、0 件は上流異常（IdP 障害）か、
    -- 鍵の issuer フィルター（collect_keys）で全滅した設定不整合のいずれかである。
    -- ここで正常としてキャッシュしてしまうと、空の鍵セットが METADATA_TTL の間
    -- キャッシュされ続け、その間の全トークンが本来の 502（上流異常）ではなく
    -- 401（トークン不正）として扱われてしまうため、ロード失敗として fail-close する
    return nil, "no usable keys in JWKS"
  end

  -- ---- v1.0 メタデータ（allow_v1_tokens 有効時のみ）----
  local issuer_v1
  local keys_v1
  if conf.allow_v1_tokens then
    -- v1.0 の OpenID configuration は /v2.0 を含まないパス
    -- （docs/obo/05: v1.0 トークンは v1.0 メタデータで検証する）
    local v1_config_url = util.build_tenant_url(conf.identity_base_url, conf.tenant_id,
        ".well-known/openid-configuration")
    local v1_oidc, v1_err = http_get_json(conf, v1_config_url)
    if not v1_oidc then
      return nil, v1_err
    end

    issuer_v1, v1_err = validate_v1_metadata_issuer(conf, v1_oidc.issuer, issuer_tenant)
    if not issuer_v1 then
      return nil, v1_err
    end

    if type(v1_oidc.jwks_uri) ~= "string" then
      return nil, "jwks_uri missing in v1.0 openid-configuration"
    end
    -- v1.0 の jwks_uri も v2.0 と同じルール（identity_base_url と同一 authority）で検証する
    local v1_ok_uri, v1_uri_err = validate_jwks_uri(conf, v1_oidc.jwks_uri)
    if not v1_ok_uri then
      return nil, v1_uri_err
    end

    local v1_jwks, v1_jwks_err = http_get_json(conf, v1_oidc.jwks_uri)
    if not v1_jwks then
      return nil, v1_jwks_err
    end
    if type(v1_jwks.keys) ~= "table" then
      return nil, "keys missing in v1.0 JWKS"
    end
    -- v1.0 の鍵は v2.0 とは別のマップに集める（フォールバックしないため。collect_keys のコメント参照）
    keys_v1 = {}
    collect_keys(v1_jwks.keys, issuer_v1, issuer_tenant, keys_v1)
    if next(keys_v1) == nil then
      -- v2.0 側と同じ理由（上記コメント参照）で fail-close する。ここで空のまま通してしまうと
      -- 「空の v1.0 JWKS からは v1.0 トークンを絶対に受理できない」という保証が崩れる
      return nil, "no usable keys in v1.0 JWKS"
    end
  end

  return { issuer = issuer, issuer_v1 = issuer_v1, keys_v2 = keys_v2, keys_v1 = keys_v1 }
end

-- テナントごとの JWKS キャッシュキーを作るローカル関数。
-- allow_v1_tokens をキーに含める理由: 同一テナントを指すフラグ有無の別設定（別ルート等）が
-- エントリを共有すると、v1 情報（issuer_v1 / v1 鍵）を持たないエントリをフラグあり設定が
-- 引いてしまい、v1.0 トークンが TTL 満了まで失敗し続けるため（設計書 §5.2）
local function jwks_cache_key(conf)
  return "obo:jwks:" .. conf.identity_base_url .. ":" .. conf.tenant_id
      .. ":v1=" .. tostring(conf.allow_v1_tokens == true)
end

-- キャッシュ経由でメタデータを取得し、conf.issuer（ピン）を毎回照合するローカル関数。
-- キャッシュキー（identity_base_url + tenant_id）には issuer が含まれず、同じテナントを
-- 指す別のプラグイン設定（別ルート等）とキャッシュエントリが共有されるため、
-- ロード時（キャッシュミス時）の照合だけではキャッシュヒット経路でピンが迂回されてしまう。
-- 正の防御としてここで毎回照合する（文字列比較 1 回なのでコストは無視できる）。
-- @return メタデータテーブル { issuer, issuer_v1, keys }。
--         issuer_v1 は allow_v1_tokens 無効時は nil。失敗時は nil, err
local function get_cached_metadata(conf, cache_key)
  local meta, err = kong.cache:get(cache_key, { ttl = METADATA_TTL }, load_metadata, conf)
  if not meta then
    return nil, tostring(err)
  end
  if conf.issuer ~= nil and conf.issuer ~= meta.issuer then
    return nil, "openid-configuration issuer does not match configured issuer"
  end
  return meta
end

-- kid に対応する署名鍵と検証済み issuer を返すローカル関数
-- 見つからない場合は 1 回だけ再取得を試み、取得に成功したときのみキャッシュを置換する
-- （鍵ロールオーバー対応。取得失敗時は既存の stale キャッシュを温存する。Issue #3）
-- @param use_v1_keys truthy なら v1.0 鍵セット（meta.keys_v1）から、falsy なら v2.0 鍵セット
--        （meta.keys_v2）から kid を引く。呼び出し元（M.validate）がトークンの ver から決める。
--        もう一方の集合へのフォールバックは行わない（Microsoft の検証手順どおり、
--        ver に対応するメタデータ文書の鍵だけで検証する。docs/obo/05。外部レビュー指摘 High）
-- @return { jwk_json = JWK の JSON 文字列, issuer = 検証済み v2.0 メタデータ issuer,
--           issuer_v1 = 検証済み v1.0 メタデータ issuer（allow_v1_tokens 無効時は nil）}。
--         失敗時は nil, err, is_upstream_error。
--   is_upstream_error が true の場合、失敗理由は「受信トークンが不正」ではなく
--   「Entra ID（OpenID configuration / JWKS）に接続できない、または応答が不正な形」であることを示す。
--   設計書（docs/superpowers/specs/2026-07-10-obo-plugin-design.md §5）のマッピングで
--   「受信 JWT の検証失敗 → 401」と「Entra ID への接続失敗 / 5xx → 502」を区別するために使う。
local function get_signing_key(conf, kid, use_v1_keys)
  local cache_key = jwks_cache_key(conf)

  local meta, err = get_cached_metadata(conf, cache_key)
  if not meta then
    -- メタデータの取得失敗は Entra ID への接続・応答形式の問題、ピン不一致は
    -- 設定とメタデータの不整合。いずれも受信トークン自体の不正ではない
    return nil, err, true
  end
  local key_set = use_v1_keys and meta.keys_v1 or meta.keys_v2
  if key_set and key_set[kid] then
    return { jwk_json = key_set[kid], issuer = meta.issuer, issuer_v1 = meta.issuer_v1 }
  end

  -- 未知 kid での再取得はワーカー単位で頻度制限する。
  -- 認証不要でここまで到達できるため、制限なしだと乱数 kid を送り続けるだけで
  -- 共有キャッシュ（cluster 全体）への無効化を連打できてしまう
  local now = ngx.time()
  local last = last_refetch[cache_key]
  if last and (now - last) < JWKS_REFETCH_INTERVAL then
    -- 直前の再取得が失敗している場合、この抑止期間中は同じ IdP 障害が続いている
    -- 可能性が高い。「kid が見つからない」（401 相当）ではなく upstream エラー
    -- （502 相当）として分類し、クライアントに誤ったシグナルを返さない
    if last_refetch_failed[cache_key] then
      return nil, "JWKS refetch recently failed (refetch suppressed)", true
    end
    return nil, "no key found in JWKS for kid (refetch suppressed)"
  end
  last_refetch[cache_key] = now

  -- Issue #3: 「取得成功後に置換」方式。kong.cache:renew を使う。
  -- 先に invalidate してから取り直す方式だと、再取得が失敗したとき（IdP 一時断など）に
  -- 本来まだ METADATA_TTL 有効だった正常な JWKS まで失い、以後の正当なトークンも
  -- IdP 復旧まで 502 になる。renew はこの問題を仕組みとして解決する。
  --
  -- renew の実装根拠（Kong 3.9.2 / 3.14.0.7 のコンテナ内ソースで裏取り済み。
  -- kong/cache/init.lua と kong/resty/mlcache/init.lua）:
  --   * コールバック（load_metadata）は get の L3 コールバックと同じキー単位ロックの中で
  --     実行される。同一ノード内で複数ワーカーに未知 kid が同時到達しても取得は直列化され、
  --     待機中に他ワーカーが更新済みならバージョン比較でコールバック自体をスキップする。
  --   * コールバックが失敗（nil, err）した場合は shm に一切書き込まず err を返す。
  --     つまり既存の stale キャッシュはロック下で温存される（delete → set の隙間がない）。
  --   * 成功時はロック下で shm を新値に置換し、ノード内ワーカーへの IPC のみ配信する。
  --     クラスタイベント（cluster_events:broadcast）は使わないため、他ノードの正常な
  --     キャッシュを消すことがない（他ノードは各自の未知 kid 検出時に各自 renew する）。
  --     クラスタ全体へ無効化を配信する kong.cache:invalidate はここでは使ってはならない。
  local fresh, renew_err = kong.cache:renew(cache_key, { ttl = METADATA_TTL }, load_metadata, conf)
  if not fresh then
    -- 再取得失敗: 既存キャッシュ（stale だが有効）は renew が温存している。
    -- 失敗理由は Entra ID への接続・応答形式の問題、またはキャッシュ層の書き込み異常で
    -- あり、いずれも受信トークンの不正ではないので upstream エラーとして返す。
    -- 続く抑止期間中の未知 kid も同じ分類にできるよう、失敗をキー単位で記録する
    last_refetch_failed[cache_key] = true
    return nil, tostring(renew_err), true
  end
  -- 再取得成功: 失敗フラグを解除する（以後の抑止期間中の未知 kid は 401 分類に戻る）
  last_refetch_failed[cache_key] = nil

  -- renew が返した値にもピンを毎回照合する。renew は他ワーカーが先に更新した値を
  -- そのまま返すことがあり（バージョン比較によるコールバックスキップ）、その場合は
  -- この conf の load_metadata（ロード時ピン照合）を経由していないため
  if conf.issuer ~= nil and conf.issuer ~= fresh.issuer then
    return nil, "openid-configuration issuer does not match configured issuer", true
  end

  local fresh_key_set = use_v1_keys and fresh.keys_v1 or fresh.keys_v2
  if fresh_key_set and fresh_key_set[kid] then
    return { jwk_json = fresh_key_set[kid], issuer = fresh.issuer, issuer_v1 = fresh.issuer_v1 }
  end
  -- IdP には正常に接続できたが、この kid の鍵が存在しない
  -- （鍵ロールオーバーに追従できていない、不正な kid、または issuer 不一致で除外された鍵）
  return nil, "no key found in JWKS for kid"
end

-- 受信アクセストークンを検証する（このモジュールの唯一の公開関数）
-- @param conf プラグイン設定
-- @param token JWT 文字列
-- @return 検証済みクレームのテーブル。
--         失敗時は nil, エラー理由（内部ログ専用。レスポンスに出さない）, is_upstream_error。
--         is_upstream_error が truthy の場合、原因は受信トークンではなく Entra ID への
--         接続失敗・応答異常。呼び出し元（handler）はこれを 401 ではなく 502 として扱うべき
--         （docs/superpowers/specs/2026-07-10-obo-plugin-design.md §5）。
function M.validate(conf, token)
  local jwt, err = decode_jwt(token)
  if not jwt then
    return nil, err
  end

  -- alg の固定チェック: RS256 以外は受け付けない
  -- （"none" や HS256 を受け入れると署名検証を骨抜きにされる。docs/obo/05: Entra は RS256）
  if jwt.header.alg ~= "RS256" then
    return nil, "unsupported alg: " .. tostring(jwt.header.alg)
  end
  if type(jwt.header.kid) ~= "string" then
    return nil, "kid missing in JWT header"
  end

  -- ver に対応する鍵セットを選ぶ。ver はこの時点ではまだ署名検証前の未検証値だが、
  -- 「鍵セットの選択」に使うのは安全である — 偽の ver で別セットを選んでも、署名がその
  -- セットの鍵で検証できなければ拒否されるだけであり、逆に検証できてしまった場合は
  -- （＝そのセットの正当な鍵で署名されたトークンだった場合は）署名済みペイロード内の
  -- ver として後段の iss 分岐でも同じ値が使われるため、攻撃者が ver 詐称によって
  -- 得られるものは何もない
  local use_v1_keys = (jwt.payload.ver == "1.0" and conf.allow_v1_tokens == true)

  local key, key_err, key_upstream = get_signing_key(conf, jwt.header.kid, use_v1_keys)
  if not key then
    return nil, key_err, key_upstream
  end

  -- kid は一致したが JWK 自体が壊れている（n/e が不正等）場合、受信トークンではなく
  -- Entra ID 側データの異常なので、他の JWKS 取得失敗と同様に upstream エラーとして扱う
  local pk, pkey_err = jwk_to_pkey(key.jwk_json)
  if not pk then
    return nil, "failed to load JWK: " .. tostring(pkey_err), true
  end

  -- RS256 署名検証（SHA-256 + PKCS#1 v1.5 は lua-resty-openssl の既定パディング）
  local ok = pk:verify(jwt.signature, jwt.signing_input, "sha256")
  if not ok then
    return nil, "signature verification failed"
  end

  -- ---- クレーム検証（署名検証が通ってから行う）----
  local claims = jwt.payload

  -- iss: 期待値を ver クレームで分岐する。ver は署名済みペイロード内にあるため、
  -- 署名検証を通過した後は改ざんの心配なく分岐に使える。
  -- 期待値はどの分岐でも「検証済みメタデータ由来の issuer」のみ（fail-close モデル。
  -- conf.issuer は v2.0 メタデータ issuer のピンとして load_metadata 側で照合済み）:
  --   ver = "2.0" → v2.0 メタデータの issuer（docs/obo/05: OpenID Connect Core の
  --                 「メタデータの Issuer Identifier と iss クレームの完全一致」）
  --   ver = "1.0" → allow_v1_tokens 有効時のみ、v1.0 メタデータの issuer
  --                 （https://sts.windows.net/{tid}/ 形式。docs/obo/05）
  --   それ以外（欠落・未知の値）→ 拒否（Entra のアクセストークンは必ず ver を含む）
  local expected_iss
  if claims.ver == "2.0" then
    expected_iss = key.issuer
  elseif claims.ver == "1.0" and conf.allow_v1_tokens then
    -- issuer_v1 は allow_v1_tokens 有効時のメタデータロードで必ず設定される（fail-close。
    -- 万一 nil でも「iss ~= nil」で必ず不一致になり、受理側に倒れることはない）
    expected_iss = key.issuer_v1
  elseif claims.ver == "1.0" then
    -- 診断ヒント（debug ログ専用。handler がレスポンスに出さないことは既存方針のまま）。
    -- 恒久対処は middle-tier アプリの api.requestedAccessTokenVersion を 2 にすること
    -- （docs/obo/08 §2.3）。アプリ登録を変更できない場合のみ allow_v1_tokens を使う
    return nil, "v1.0 token rejected: set requestedAccessTokenVersion=2 on the app registration (docs/obo/08), or enable allow_v1_tokens"
  else
    return nil, "unsupported or missing ver claim"
  end
  if claims.iss ~= expected_iss then
    return nil, "issuer mismatch"
  end

  -- aud: 自分（middle-tier アプリ）宛てのトークンだけを受け入れる。
  -- 他アプリ宛てのトークンは OBO で引き換えできないため、ここで拒否する（docs/obo/02）。
  -- aud の形式はトークンバージョンで異なり得る（v2.0 は素の client_id、v1.0 は
  -- api://{client_id} が典型。docs/obo/05）ため、conf.audiences（複数）の
  -- いずれか 1 つとの完全一致とする
  local aud_ok = false
  for _, expected_aud in ipairs(conf.audiences) do
    if claims.aud == expected_aud then
      aud_ok = true
      break
    end
  end
  if not aud_ok then
    return nil, "audience mismatch"
  end

  -- exp: 必須（RFC 7523 Section 3）。期限切れは拒否
  local now = ngx.time()
  if type(claims.exp) ~= "number" or now > claims.exp + CLOCK_SKEW then
    return nil, "token expired or exp missing"
  end

  -- nbf: 存在する場合のみ検証（RFC 7523 では任意クレーム）
  if claims.nbf ~= nil then
    if type(claims.nbf) ~= "number" or now < claims.nbf - CLOCK_SKEW then
      return nil, "token not yet valid"
    end
  end

  return claims
end

return M
