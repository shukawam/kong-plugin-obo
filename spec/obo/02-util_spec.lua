-- Base64URL エンコード/デコードのテスト
-- JWT（RFC 7515）は通常の Base64 ではなく、パディングなし・URL 安全な Base64URL を使う

describe("obo: util (unit)", function()
  local util

  setup(function()
    util = require("kong.plugins.obo.util")
  end)

  teardown(function()
    package.loaded["kong.plugins.obo.util"] = nil
  end)

  it("エンコードとデコードで元に戻る（ラウンドトリップ）", function()
    local inputs = { "a", "ab", "abc", "abcd", "\0\1\2\255", string.rep("x", 1000) }
    for _, s in ipairs(inputs) do
      assert.equal(s, util.b64url_decode(util.b64url_encode(s)))
    end
  end)

  it("パディング文字 = を含まない", function()
    assert.is_nil(util.b64url_encode("a"):find("=", 1, true))
    assert.is_nil(util.b64url_encode("ab"):find("=", 1, true))
  end)

  it("+ と / の代わりに - と _ を使う", function()
    -- 0xFB 0xEF は通常の Base64 で "++8" になるバイト列
    local encoded = util.b64url_encode("\251\239")
    assert.is_nil(encoded:find("+", 1, true))
    assert.is_nil(encoded:find("/", 1, true))
  end)

  it("既知の値: RFC 4648 テストベクター", function()
    assert.equal("Zm9vYmFy", util.b64url_encode("foobar"))
    assert.equal("foobar", util.b64url_decode("Zm9vYmFy"))
  end)

  it("不正な入力のデコードは nil を返す", function()
    assert.is_nil(util.b64url_decode("a"))      -- 長さ 4n+1 はあり得ない
    assert.is_nil(util.b64url_decode(nil))
    assert.is_nil(util.b64url_decode(12345))
  end)
end)

describe("obo: fixtures (unit)", function()
  it("jwt.make が作ったトークンをフィクスチャの公開鍵で検証できる", function()
    local pkey = require "resty.openssl.pkey"
    local util = require "kong.plugins.obo.util"
    local keys = require "spec.fixtures.obo.keys"
    local jwt  = require "spec.fixtures.obo.jwt"

    local token = jwt.make()
    local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    assert.is_truthy(h)

    local pk = assert(pkey.new(keys.public_pem))
    assert.is_true(pk:verify(util.b64url_decode(s), h .. "." .. p, "sha256"))
  end)

  it("keys.jwk() が n と e を含む RSA JWK を返す", function()
    local jwk = require("spec.fixtures.obo.keys").jwk()
    assert.equal("RSA", jwk.kty)
    assert.equal("test-key-1", jwk.kid)
    assert.is_string(jwk.n)
    assert.is_string(jwk.e)
  end)
end)
