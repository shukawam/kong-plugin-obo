-- テスト用の署名付き JWT を生成するヘルパー
-- 本物の Entra ID が発行するトークンの代わりに、テスト鍵で署名した JWT を作る。
-- exp/nbf は実行時刻からの相対値なので、テストが時間経過で壊れない。

local cjson = require "cjson.safe"
local pkey  = require "resty.openssl.pkey"
local util  = require "kong.plugins.obo.util"
local keys  = require "spec.fixtures.obo.keys"

local M = {}

-- 署名済みテスト JWT を作る
-- @param claims_override 既定クレームを上書きするテーブル（例: { aud = "other" }）。
--                        値に cjson.null ではなく nil を入れたい場合は上書きではなく既定値を変えること
-- @param header_override 既定ヘッダーを上書きするテーブル（kid 不一致などの異常系テスト用）
-- @return JWT 文字列
function M.make(claims_override, header_override)
  local now = ngx.time()

  -- 既定クレーム: jwt_validator のテスト・統合テストの「正しいトークン」の姿
  local claims = {
    iss = "https://login.microsoftonline.com/test-tenant/v2.0",
    aud = "test-client-id",
    sub = "test-user",
    exp = now + 3600,
    nbf = now,
  }
  for k, v in pairs(claims_override or {}) do
    claims[k] = v
  end

  local header = { alg = "RS256", typ = "JWT", kid = keys.kid }
  for k, v in pairs(header_override or {}) do
    header[k] = v
  end

  -- JWT は base64url(header) . base64url(payload) . base64url(署名) の 3 部構成
  local signing_input = util.b64url_encode(cjson.encode(header))
      .. "." .. util.b64url_encode(cjson.encode(claims))

  local pk = assert(pkey.new(keys.private_pem))
  -- RS256 = SHA-256 + PKCS#1 v1.5 パディング（lua-resty-openssl の既定）
  local sig = assert(pk:sign(signing_input, "sha256"))

  return signing_input .. "." .. util.b64url_encode(sig)
end

return M
