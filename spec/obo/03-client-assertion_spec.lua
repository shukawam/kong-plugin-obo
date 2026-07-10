-- client assertion（private_key_jwt 方式のクライアント認証 JWT）生成のテスト
-- 仕様: docs/obo/04-client-assertion.md

local cjson = require "cjson.safe"

describe("obo: client_assertion (unit)", function()
  local client_assertion, util, keys
  local conf, token_endpoint

  setup(function()
    -- kong.log だけあれば動くように最小限モック
    _G.kong = { log = { debug = function() end, err = function() end } }
    client_assertion = require("kong.plugins.obo.client_assertion")
    util = require("kong.plugins.obo.util")
    keys = require("spec.fixtures.obo.keys")
  end)

  teardown(function()
    _G.kong = nil
    package.loaded["kong.plugins.obo.client_assertion"] = nil
  end)

  before_each(function()
    conf = {
      client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      private_key = keys.private_pem,
      certificate_thumbprint = "TEST_THUMBPRINT_B64URL",
    }
    token_endpoint = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"
  end)

  -- JWT を分解してヘッダーとペイロードのテーブルを返すテスト用ローカル関数
  local function decode(jwt)
    local h, p = jwt:match("^([^.]+)%.([^.]+)%.[^.]+$")
    return cjson.decode(util.b64url_decode(h)), cjson.decode(util.b64url_decode(p))
  end

  it("PS256 / JWT / x5t#S256 のヘッダーを持つ", function()
    local jwt = assert(client_assertion.build(conf, token_endpoint))
    local header = decode(jwt)
    assert.equal("PS256", header.alg)
    assert.equal("JWT", header.typ)
    assert.equal("TEST_THUMBPRINT_B64URL", header["x5t#S256"])
  end)

  it("必要なクレームをすべて含む（docs/obo/04 の 7 クレーム）", function()
    local before = ngx.time()
    local jwt = assert(client_assertion.build(conf, token_endpoint))
    local _, payload = decode(jwt)

    assert.equal(token_endpoint, payload.aud)      -- aud はトークンエンドポイント URL
    assert.equal(conf.client_id, payload.iss)      -- iss はクライアント ID
    assert.equal(conf.client_id, payload.sub)      -- sub は iss と同一
    assert.is_string(payload.jti)                  -- jti は一意識別子
    assert.is_number(payload.nbf)
    assert.is_number(payload.iat)
    assert.is_number(payload.exp)
    -- nbf は現在時刻、exp は「nbf の 5〜10 分後まで」の公式推奨に収まること
    assert.is_true(payload.nbf >= before - 5 and payload.nbf <= ngx.time() + 5)
    assert.is_true(payload.exp > payload.nbf)
    assert.is_true(payload.exp - payload.nbf <= 600)
  end)

  it("jti は呼び出しごとに異なる", function()
    local _, p1 = decode(assert(client_assertion.build(conf, token_endpoint)))
    local _, p2 = decode(assert(client_assertion.build(conf, token_endpoint)))
    assert.not_equal(p1.jti, p2.jti)
  end)

  it("署名が RSA-PSS (PS256) として検証できる", function()
    local pkey = require "resty.openssl.pkey"
    local jwt = assert(client_assertion.build(conf, token_endpoint))
    local h, p, s = jwt:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    local pk = assert(pkey.new(keys.public_pem))
    -- PS256 検証: PSS パディングを明示する（docs/obo/04「Use PSS padding」）
    assert.is_true(pk:verify(util.b64url_decode(s), h .. "." .. p, "sha256",
                             pkey.PADDINGS.RSA_PKCS1_PSS_PADDING))
  end)

  it("不正な秘密鍵なら nil とエラーを返す", function()
    conf.private_key = "not a pem"
    local jwt, err = client_assertion.build(conf, token_endpoint)
    assert.is_nil(jwt)
    assert.is_string(err)
  end)
end)
