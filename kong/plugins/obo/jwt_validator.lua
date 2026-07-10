-- 受信アクセストークン（クライアントが送ってきた Bearer トークン）の検証
-- 仕様: docs/obo/05-token-validation.md
--   1. OpenID configuration（v2.0）から jwks_uri を取得（kong.cache でキャッシュ）
--   2. JWKS を取得し、トークンヘッダーの kid で公開鍵を選択
--      未知の kid はキャッシュを破棄して 1 回だけ再取得（鍵ロールオーバー追従）
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
  -- v2.0 のメタデータ URL（docs/obo/05）
  local config_url = conf.identity_base_url .. "/" .. conf.tenant_id
      .. "/v2.0/.well-known/openid-configuration"
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
-- 見つからない場合はキャッシュを破棄して 1 回だけ再取得する（鍵ロールオーバー対応）
local function get_jwk_for_kid(conf, kid)
  local cache_key = jwks_cache_key(conf)

  local by_kid, err = kong.cache:get(cache_key, { ttl = METADATA_TTL }, load_jwks, conf)
  if not by_kid then
    return nil, tostring(err)
  end
  if by_kid[kid] then
    return by_kid[kid]
  end

  -- キャッシュが古い可能性があるので、無効化して取り直す
  kong.cache:invalidate(cache_key)
  by_kid, err = kong.cache:get(cache_key, { ttl = METADATA_TTL }, load_jwks, conf)
  if not by_kid then
    return nil, tostring(err)
  end
  if by_kid[kid] then
    return by_kid[kid]
  end
  return nil, "no key found in JWKS for kid"
end

-- 受信アクセストークンを検証する（このモジュールの唯一の公開関数）
-- @param conf プラグイン設定
-- @param token JWT 文字列
-- @return 検証済みクレームのテーブル。失敗時は nil とエラー理由（内部ログ専用。レスポンスに出さない）
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

  local jwk_json, key_err = get_jwk_for_kid(conf, jwt.header.kid)
  if not jwk_json then
    return nil, key_err
  end

  local pk, pkey_err = pkey.new(jwk_json, { format = "JWK" })
  if not pk then
    return nil, "failed to load JWK: " .. tostring(pkey_err)
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
      or (conf.identity_base_url .. "/" .. conf.tenant_id .. "/v2.0")
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
