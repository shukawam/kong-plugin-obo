-- ============================================================
-- テスト専用の RSA 鍵ペア。絶対に本番環境で使用しないこと。
-- 再生成する場合:
--   openssl genrsa -out spec/fixtures/obo/rsa_key.pem 2048
--   openssl rsa -in spec/fixtures/obo/rsa_key.pem -pubout -out spec/fixtures/obo/rsa_pub.pem
-- ============================================================

local M = {}

-- このファイル自身の絶対パスから、鍵ファイルが置かれたディレクトリを求める
-- pongo（busted）実行時のカレントディレクトリはリポジトリルートではない
-- （実測: /kong-plugin ではなく /kong）ため、cwd 相対パスに頼らずこの方法で解決する
local function this_dir()
  local source = debug.getinfo(1, "S").source
  if source:sub(1, 1) == "@" then
    source = source:sub(2)
  end
  return source:match("(.*/)") or "./"
end

-- ファイルを読み込むローカル関数
local function read_file(path)
  local f = assert(io.open(path, "r"), "fixture not found: " .. path)
  local content = f:read("*a")
  f:close()
  return content
end

M.private_pem = read_file(this_dir() .. "rsa_key.pem")
M.public_pem  = read_file(this_dir() .. "rsa_pub.pem")

-- テスト用の鍵 ID。JWT ヘッダーの kid と JWKS の kid をこれで一致させる
M.kid = "test-key-1"

-- 公開鍵から JWK（JSON Web Key）テーブルを作る
-- モック IdP の JWKS エンドポイントや jwt_validator の単体テストで使う
function M.jwk()
  local pkey = require "resty.openssl.pkey"
  local util = require "kong.plugins.obo.util"
  local pk = assert(pkey.new(M.public_pem))
  -- RSA 公開鍵のパラメータ n（modulus）と e（exponent）を取り出す
  local params = pk:get_parameters()
  return {
    kty = "RSA",
    use = "sig",
    kid = M.kid,
    n = util.b64url_encode(params.n:to_binary()),
    e = util.b64url_encode(params.e:to_binary()),
  }
end

return M
