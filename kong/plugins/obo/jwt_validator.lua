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

-- OpenID 設定 → JWKS の順に取得し、kid → JWK(JSON文字列) のテーブルを作るローカル関数
-- kong.cache のコールバックとして呼ばれる（キャッシュミス時のみ実行される）
local function load_jwks(conf)
  -- v2.0 のメタデータ URL（docs/obo/05）。URL 連結は util.build_tenant_url に集約
  local config_url = util.build_tenant_url(conf.identity_base_url, conf.tenant_id,
      "v2.0/.well-known/openid-configuration")
  local oidc, err = http_get_json(conf, config_url)
  if not oidc then
    return nil, err
  end
  if type(oidc.jwks_uri) ~= "string" then
    return nil, "jwks_uri missing in openid-configuration"
  end

  local jwks, jwks_err = http_get_json(conf, oidc.jwks_uri)
  if not jwks then
    return nil, jwks_err
  end
  if type(jwks.keys) ~= "table" then
    return nil, "keys missing in JWKS"
  end

  -- kid で引けるように整形する。pkey.new に渡せるよう JWK は JSON 文字列のまま保持する
  local by_kid = {}
  for _, jwk in ipairs(jwks.keys) do
    if type(jwk) == "table" and type(jwk.kid) == "string" then
      by_kid[jwk.kid] = cjson.encode(jwk)
    end
  end
  return by_kid
end

-- テナントごとの JWKS キャッシュキーを作るローカル関数
local function jwks_cache_key(conf)
  return "obo:jwks:" .. conf.identity_base_url .. ":" .. conf.tenant_id
end

-- kid に対応する JWK(JSON文字列) を返すローカル関数
-- 見つからない場合は 1 回だけ再取得を試み、取得に成功したときのみキャッシュを置換する
-- （鍵ロールオーバー対応。取得失敗時は既存の stale キャッシュを温存する。Issue #3）
-- @return jwk_json, err, is_upstream_error
--   is_upstream_error が true の場合、失敗理由は「受信トークンが不正」ではなく
--   「Entra ID（OpenID configuration / JWKS）に接続できない、または応答が不正な形」であることを示す。
--   設計書（docs/superpowers/specs/2026-07-10-obo-plugin-design.md §5）のマッピングで
--   「受信 JWT の検証失敗 → 401」と「Entra ID への接続失敗 / 5xx → 502」を区別するために使う。
local function get_jwk_for_kid(conf, kid)
  local cache_key = jwks_cache_key(conf)

  local by_kid, err = kong.cache:get(cache_key, { ttl = METADATA_TTL }, load_jwks, conf)
  if not by_kid then
    -- load_jwks の失敗は常に Entra ID への接続・応答形式の問題であり、
    -- 受信トークン自体の不正ではない
    return nil, tostring(err), true
  end
  if by_kid[kid] then
    return by_kid[kid]
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
  --   * コールバック（load_jwks）は get の L3 コールバックと同じキー単位ロックの中で
  --     実行される。同一ノード内で複数ワーカーに未知 kid が同時到達しても取得は直列化され、
  --     待機中に他ワーカーが更新済みならバージョン比較でコールバック自体をスキップする。
  --   * コールバックが失敗（nil, err）した場合は shm に一切書き込まず err を返す。
  --     つまり既存の stale キャッシュはロック下で温存される（delete → set の隙間がない）。
  --   * 成功時はロック下で shm を新値に置換し、ノード内ワーカーへの IPC のみ配信する。
  --     クラスタイベント（cluster_events:broadcast）は使わないため、他ノードの正常な
  --     キャッシュを消すことがない（他ノードは各自の未知 kid 検出時に各自 renew する）。
  --     クラスタ全体へ無効化を配信する kong.cache:invalidate はここでは使ってはならない。
  local fresh, renew_err = kong.cache:renew(cache_key, { ttl = METADATA_TTL }, load_jwks, conf)
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

  if fresh[kid] then
    return fresh[kid]
  end
  -- IdP には正常に接続できたが、この kid の鍵が存在しない
  -- （鍵ロールオーバーに追従できていない、または不正な kid を送ってきた）
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

  local jwk_json, key_err, key_upstream = get_jwk_for_kid(conf, jwt.header.kid)
  if not jwk_json then
    return nil, key_err, key_upstream
  end

  -- kid は一致したが JWK 自体が壊れている（n/e が不正等）場合、受信トークンではなく
  -- Entra ID 側データの異常なので、他の JWKS 取得失敗と同様に upstream エラーとして扱う
  local pk, pkey_err = pkey.new(jwk_json, { format = "JWK" })
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

  -- iss: メタデータの issuer と完全一致が原則（docs/obo/05）。
  -- conf.issuer 未指定なら v2.0 の形式（{base}/{tenant}/v2.0）を導出する
  local expected_iss = conf.issuer
      or util.build_tenant_url(conf.identity_base_url, conf.tenant_id, "v2.0")
  if claims.iss ~= expected_iss then
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
