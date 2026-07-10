-- private_key_jwt 方式のクライアント認証に使う client assertion（署名付き JWT）の生成
-- 仕様: docs/obo/04-client-assertion.md
--   - ヘッダー: alg=PS256, typ=JWT, x5t#S256=証明書サムプリント
--   - クレーム: aud(トークンエンドポイント), iss=sub=client_id, jti, nbf, iat, exp(nbf+5分)
--   - 署名: RSA-PSS（PSS パディング）

local pkey  = require "resty.openssl.pkey"
local cjson = require "cjson.safe"
local util  = require "kong.plugins.obo.util"
local utils = require "kong.tools.utils"  -- uuid() を使う（Kong 同梱）

local M = {}

-- assertion の有効期間（秒）。公式推奨「nbf の 5〜10 分後まで」に収める
local ASSERTION_LIFETIME = 300

-- client assertion JWT を生成する
-- @param conf プラグイン設定（client_id, private_key, certificate_thumbprint を使用）
-- @param token_endpoint aud クレームに入れるトークンエンドポイント URL
-- @return 署名済み JWT 文字列。失敗時は nil とエラーメッセージ（ログ用。鍵の中身を含めないこと）
function M.build(conf, token_endpoint)
  local now = ngx.time()

  local header = {
    alg = "PS256",
    typ = "JWT",
    -- 証明書 DER の SHA-256 サムプリント（Base64url）。Entra ID が鍵を特定するのに使う
    ["x5t#S256"] = conf.certificate_thumbprint,
  }

  local payload = {
    aud = token_endpoint,
    iss = conf.client_id,
    sub = conf.client_id,  -- 自己発行のため iss と同一（docs/obo/04, RFC 7523）
    jti = utils.uuid(),    -- リプレイ防止のため毎回一意な値にする
    nbf = now,
    iat = now,
    exp = now + ASSERTION_LIFETIME,
  }

  local signing_input = util.b64url_encode(cjson.encode(header))
      .. "." .. util.b64url_encode(cjson.encode(payload))

  local pk, err = pkey.new(conf.private_key)
  if not pk then
    return nil, "failed to load private key: " .. tostring(err)
  end

  -- PS256 = SHA-256 + RSA-PSS パディング（docs/obo/04「Use PSS padding」）
  local sig, sign_err = pk:sign(signing_input, "sha256", pkey.PADDINGS.RSA_PKCS1_PSS_PADDING)
  if not sig then
    return nil, "failed to sign client assertion: " .. tostring(sign_err)
  end

  return signing_input .. "." .. util.b64url_encode(sig)
end

return M
