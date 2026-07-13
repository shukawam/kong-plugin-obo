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

describe("obo: util.build_tenant_url (unit)", function()
  local util

  setup(function()
    util = require("kong.plugins.obo.util")
  end)

  teardown(function()
    package.loaded["kong.plugins.obo.util"] = nil
  end)

  it("base / tenant / path を連結する", function()
    assert.equal(
      "https://login.microsoftonline.com/tenant-x/oauth2/v2.0/token",
      util.build_tenant_url("https://login.microsoftonline.com", "tenant-x", "oauth2/v2.0/token"))
  end)

  it("path を省略すると base/tenant までを返す", function()
    assert.equal(
      "https://login.microsoftonline.com/tenant-x",
      util.build_tenant_url("https://login.microsoftonline.com", "tenant-x"))
  end)

  it("base の末尾スラッシュを正規化して // を作らない", function()
    -- 設定に末尾スラッシュが付いていても issuer が ...//tenant/v2.0 にならないこと
    assert.equal(
      "https://login.microsoftonline.com/tenant-x/v2.0",
      util.build_tenant_url("https://login.microsoftonline.com/", "tenant-x", "v2.0"))
  end)

  it("末尾スラッシュが複数連続していても 1 個に正規化する", function()
    assert.equal(
      "https://login.microsoftonline.com/tenant-x/v2.0",
      util.build_tenant_url("https://login.microsoftonline.com///", "tenant-x", "v2.0"))
  end)

  it("tenant_id を小文字に正規化する（Entra のメタデータ issuer は小文字 GUID を返すため）", function()
    -- 大文字 GUID を設定しても、導出 issuer / メタデータ URL / トークンエンドポイントが
    -- Entra の正規形（小文字 GUID）と一致するように、URL builder の入口で小文字化する。
    -- 裏取り: login.microsoftonline.com は大文字 GUID でメタデータを要求しても
    -- issuer 内の GUID を小文字で返す（実メタデータで確認済み）
    assert.equal(
      "https://login.microsoftonline.com/aaaabbbb-1111-2222-3333-444455556666/v2.0",
      util.build_tenant_url("https://login.microsoftonline.com",
                            "AAAABBBB-1111-2222-3333-444455556666", "v2.0"))
  end)

  it("base や tenant_id が文字列でなければ nil を返す（error() を投げない）", function()
    assert.is_nil(util.build_tenant_url(nil, "tenant-x", "v2.0"))
    assert.is_nil(util.build_tenant_url(12345, "tenant-x", "v2.0"))
    assert.is_nil(util.build_tenant_url("https://login.microsoftonline.com", nil, "v2.0"))
  end)

  it("ドメイン形式の tenant_id も小文字に正規化する（DNS は大文字小文字を区別しない）", function()
    assert.equal(
      "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0",
      util.build_tenant_url("https://login.microsoftonline.com",
                            "Contoso.OnMicrosoft.Com", "v2.0"))
  end)
end)

describe("obo: util.is_guid (unit)", function()
  local util

  setup(function()
    util = require("kong.plugins.obo.util")
  end)

  teardown(function()
    package.loaded["kong.plugins.obo.util"] = nil
  end)

  it("GUID（大文字小文字とも）を受理する", function()
    assert.is_true(util.is_guid("11111111-2222-3333-4444-555555555555"))
    assert.is_true(util.is_guid("AAAABBBB-1111-2222-3333-444455556666"))
  end)

  it("GUID でない文字列・非文字列を拒否する", function()
    assert.is_false(util.is_guid("contoso.onmicrosoft.com"))
    assert.is_false(util.is_guid("common"))
    assert.is_false(util.is_guid("11111111-2222-3333-4444-55555555555"))  -- 1 桁不足
    assert.is_false(util.is_guid(nil))
    assert.is_false(util.is_guid(12345))
  end)
end)

describe("obo: util.url_scheme_authority (unit)", function()
  local util

  setup(function()
    util = require("kong.plugins.obo.util")
  end)

  teardown(function()
    package.loaded["kong.plugins.obo.util"] = nil
  end)

  it("scheme と authority（host:port）を取り出す", function()
    local scheme, authority = util.url_scheme_authority("https://login.microsoftonline.com/tenant/v2.0")
    assert.equal("https", scheme)
    assert.equal("login.microsoftonline.com", authority)
  end)

  it("ポート付きの authority を取り出す", function()
    local scheme, authority = util.url_scheme_authority("http://127.0.0.1:10999/tenant/discovery/v2.0/keys")
    assert.equal("http", scheme)
    assert.equal("127.0.0.1:10999", authority)
  end)

  it("絶対 URL でなければ nil を返す", function()
    assert.is_nil(util.url_scheme_authority("/relative/path"))
    assert.is_nil(util.url_scheme_authority(nil))
    assert.is_nil(util.url_scheme_authority(12345))
  end)
end)

-- ログ出力用の無害化関数のテスト（Issue #9）
-- IdP（Entra ID）の error_description など、外部から来る文字列をそのまま debug ログに
-- 出すと、CR/LF によるログインジェクションや、巨大文字列によるログ肥大化の恐れがある
describe("obo: util.sanitize_log_value (unit)", function()
  local util

  setup(function()
    util = require("kong.plugins.obo.util")
  end)

  teardown(function()
    package.loaded["kong.plugins.obo.util"] = nil
  end)

  it("CR/LF を含む文字列は制御文字が取り除かれ 1 行になる", function()
    local input = "AADSTS50079: some message\r\nTrace ID: abc\r\nInjected: fake log line"
    local sanitized = util.sanitize_log_value(input)
    assert.is_nil(sanitized:find("\r", 1, true))
    assert.is_nil(sanitized:find("\n", 1, true))
  end)

  it("既定の上限（256文字）を超える文字列は切り詰められる", function()
    local input = string.rep("x", 1000)
    local sanitized = util.sanitize_log_value(input)
    assert.is_true(#sanitized <= 256)
  end)

  it("max_len を指定すればその長さで切り詰められる", function()
    local input = string.rep("y", 100)
    local sanitized = util.sanitize_log_value(input, 10)
    assert.is_true(#sanitized <= 10)
  end)

  it("NUL やタブなどその他の制御文字も除去される", function()
    local input = "a\0b\tc\127d"
    local sanitized = util.sanitize_log_value(input)
    assert.is_nil(sanitized:find("\0", 1, true))
    assert.is_nil(sanitized:find("\127", 1, true))
  end)

  it("文字列以外（nil・数値・テーブル）は空文字を返す", function()
    assert.equal("", util.sanitize_log_value(nil))
    assert.equal("", util.sanitize_log_value(12345))
    assert.equal("", util.sanitize_log_value({}))
  end)

  it("制御文字も長大でもない通常の文字列はそのまま返す", function()
    assert.equal("interaction_required", util.sanitize_log_value("interaction_required"))
  end)

  -- 切り詰めはバイト長ベースで行うため、上限がマルチバイト文字（UTF-8）の途中に
  -- 当たると不完全なバイト列が末尾に残り、ログが文字化けする。切り詰め後に
  -- 文字境界へ揃える処理を検証する（Entra の error_description はローカライズされて
  -- 日本語等のマルチバイト文字を含むことがある）
  it("256 バイト境界がマルチバイト文字の途中に当たる場合、文字境界まで戻して切り詰める", function()
    -- 「あ」は UTF-8 で 3 バイト。100 文字 = 300 バイト。
    -- 256 バイト目は 86 文字目（バイト位置 256-258）の先頭バイトに当たるため、
    -- 単純なバイト切り詰めだと先頭バイト 1 個だけが末尾に残ってしまう
    local input = string.rep("あ", 100)
    local sanitized = util.sanitize_log_value(input)
    assert.equal(string.rep("あ", 85), sanitized)  -- 85 文字 = 255 バイトで完結する
  end)

  it("max_len がマルチバイト文字の継続バイトの途中に当たる場合も文字境界に揃う", function()
    -- 「あ」= E3 81 82, 「い」= E3 81 84。max_len=5 だと「い」の 2 バイト目で切れる
    assert.equal("あ", util.sanitize_log_value("あいう", 5))
    -- max_len=4 だと「い」の先頭バイトだけが残る（先頭バイトの除去も確認）
    assert.equal("あ", util.sanitize_log_value("あいう", 4))
  end)

  it("上限がちょうど文字境界に一致する場合は完全な文字を削らない", function()
    -- 2 文字 = 6 バイト。max_len=6 なら 2 文字ともそのまま残る
    assert.equal("あい", util.sanitize_log_value("あいう", 6))
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
