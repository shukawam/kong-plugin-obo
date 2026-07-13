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

-- OpenID 設定 → JWKS の順に取得し、検証済み issuer と kid → JWK(JSON文字列) の
-- テーブルをまとめて返すローカル関数。
-- kong.cache のコールバックとして呼ばれる（キャッシュミス時のみ実行される）
-- @return { issuer = 検証済み issuer, keys = { kid → JWK JSON 文字列 } }。失敗時は nil, err
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

  -- issuer のパスからテナント ID（GUID）部分を取り出す（下の署名鍵 issuer 検証で使う）
  local issuer_tenant = issuer:match("://[^/]+/([^/]+)/v2%.0$")

  -- kid で引けるように整形する。pkey.new に渡せるよう JWK は JSON 文字列のまま保持する。
  -- 署名鍵の issuer 検証（docs/obo/05 "Validate the signing key issuer"）:
  -- Entra の JWKS は鍵エントリに issuer フィールドを含むことがある（実 JWKS で確認済み。
  -- 多くは "{tenantid}" プレースホルダ入り、一部は具体的なテナント GUID）。
  -- 存在する場合はプレースホルダを実テナントに置換した上でメタデータの issuer と
  -- 完全一致しない鍵は取り込まない（他 issuer の鍵での署名検証を防ぐ）
  local by_kid = {}
  for _, jwk in ipairs(jwks.keys) do
    if type(jwk) == "table" and type(jwk.kid) == "string" then
      local key_issuer_ok = true
      if jwk.issuer ~= nil then
        if type(jwk.issuer) == "string" and issuer_tenant then
          -- gsub の第 4 引数 1 は「最初の 1 回だけ置換」。{tenantid} は Lua パターンの
          -- 特殊文字を含まないのでそのまま検索文字列に使える
          local resolved = jwk.issuer:gsub("{tenantid}", issuer_tenant, 1)
          key_issuer_ok = (resolved == issuer)
        else
          key_issuer_ok = false
        end
      end
      if key_issuer_ok then
        by_kid[jwk.kid] = cjson.encode(jwk)
      end
    end
  end
  return { issuer = issuer, keys = by_kid }
end

-- テナントごとの JWKS キャッシュキーを作るローカル関数
local function jwks_cache_key(conf)
  return "obo:jwks:" .. conf.identity_base_url .. ":" .. conf.tenant_id
end

-- キャッシュ経由でメタデータを取得し、conf.issuer（ピン）を毎回照合するローカル関数。
-- キャッシュキー（identity_base_url + tenant_id）には issuer が含まれず、同じテナントを
-- 指す別のプラグイン設定（別ルート等）とキャッシュエントリが共有されるため、
-- ロード時（キャッシュミス時）の照合だけではキャッシュヒット経路でピンが迂回されてしまう。
-- 正の防御としてここで毎回照合する（文字列比較 1 回なのでコストは無視できる）。
-- @return メタデータテーブル { issuer, keys }。失敗時は nil, err
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
-- @return { jwk_json = JWK の JSON 文字列, issuer = 検証済みメタデータ issuer }。
--         失敗時は nil, err, is_upstream_error。
--   is_upstream_error が true の場合、失敗理由は「受信トークンが不正」ではなく
--   「Entra ID（OpenID configuration / JWKS）に接続できない、または応答が不正な形」であることを示す。
--   設計書（docs/superpowers/specs/2026-07-10-obo-plugin-design.md §5）のマッピングで
--   「受信 JWT の検証失敗 → 401」と「Entra ID への接続失敗 / 5xx → 502」を区別するために使う。
local function get_signing_key(conf, kid)
  local cache_key = jwks_cache_key(conf)

  local meta, err = get_cached_metadata(conf, cache_key)
  if not meta then
    -- メタデータの取得失敗は Entra ID への接続・応答形式の問題、ピン不一致は
    -- 設定とメタデータの不整合。いずれも受信トークン自体の不正ではない
    return nil, err, true
  end
  if meta.keys[kid] then
    return { jwk_json = meta.keys[kid], issuer = meta.issuer }
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

  if fresh.keys[kid] then
    return { jwk_json = fresh.keys[kid], issuer = fresh.issuer }
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

  local key, key_err, key_upstream = get_signing_key(conf, jwt.header.kid)
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

  -- iss: メタデータの issuer と完全一致を要求する（docs/obo/05: OpenID Connect Core の
  -- 「メタデータの Issuer Identifier と iss クレームの完全一致」）。
  -- 検証済みメタデータ issuer が唯一の期待値であり、conf.issuer は
  -- メタデータ issuer のピンとして load_metadata 側で照合済み
  if claims.iss ~= key.issuer then
    return nil, "issuer mismatch"
  end

  -- aud: 自分（middle-tier アプリ）宛てのトークンだけを受け入れる。
  -- 他アプリ宛てのトークンは OBO で引き換えできないため、ここで拒否する（docs/obo/02）
  if claims.aud ~= conf.audience then
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
