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
    -- false を渡すとそのキーを削除する（例: kid = false で「kid なし」の異常系トークンを作る）
    if v == false then
      header[k] = nil
    else
      header[k] = v
    end
  end

  -- JWT は base64url(header) . base64url(payload) . base64url(署名) の 3 部構成
  local signing_input = util.b64url_encode(cjson.encode(header))
      .. "." .. util.b64url_encode(cjson.encode(claims))

  local pk = assert(pkey.new(keys.private_pem))
  -- RS256 = SHA-256 + PKCS#1 v1.5 パディング（lua-resty-openssl の既定）
  local sig = assert(pk:sign(signing_input, "sha256"))

  return signing_input .. "." .. util.b64url_encode(sig)
end

-- private_key_jwt 方式のクライアント認証で使う client assertion（PS256 署名 JWT）を作る。
-- 統合テストでモック IdP の assertion 検証（issue-6）を直接叩くために使う。
-- 既定は「モック IdP が受理すべき正しい assertion」の姿。異常系は claims_override で崩す
-- （例: { aud = "https://wrong/token" } で aud 不一致を作る）。
-- 署名を壊したい場合は戻り値の末尾を書き換える（別鍵は不要）。
-- @param claims_override 既定クレームを上書きするテーブル
-- @return client assertion JWT 文字列
function M.make_assertion(claims_override)
  local now = ngx.time()

  -- 既定クレーム（docs/obo/04）。aud は統合テストのモック IdP トークンエンドポイント URL。
  local claims = {
    aud = "http://127.0.0.1:10999/test-tenant/oauth2/v2.0/token",
    iss = "test-client-id",
    sub = "test-client-id",  -- iss と同一（docs/obo/04）
    jti = "test-jti-" .. tostring(now) .. "-" .. tostring(math.random(1e9)),
    nbf = now,
    iat = now,
    exp = now + 300,
  }
  for k, v in pairs(claims_override or {}) do
    claims[k] = v
  end

  -- ヘッダーは PS256 固定（docs/obo/04）。x5t#S256 はテストではダミー値でよい
  local header = { alg = "PS256", typ = "JWT", ["x5t#S256"] = "test-thumbprint" }

  local signing_input = util.b64url_encode(cjson.encode(header))
      .. "." .. util.b64url_encode(cjson.encode(claims))

  local pk = assert(pkey.new(keys.private_pem))
  -- PS256 = SHA-256 + RSA-PSS パディング（client_assertion.lua と同じ）
  local sig = assert(pk:sign(signing_input, "sha256", pkey.PADDINGS.RSA_PKCS1_PSS_PADDING))

  return signing_input .. "." .. util.b64url_encode(sig)
end

return M
