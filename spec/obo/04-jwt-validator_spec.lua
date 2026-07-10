-- 受信アクセストークン検証のテスト
-- 仕様: docs/obo/05-token-validation.md
-- resty.http をモックして、OpenID 設定と JWKS の取得を偽装する

local cjson = require "cjson.safe"

describe("obo: jwt_validator (unit)", function()
  local jwt_validator, jwt, keys
  local conf
  local http_responses   -- URL → レスポンスのテーブル（各テストで設定）
  local http_call_count  -- HTTP 呼び出し回数（キャッシュ検証用）

  setup(function()
    -- resty.http のモック。jwt_validator を require する前に差し込むこと
    package.loaded["resty.http"] = {
      new = function()
        return {
          set_timeout = function() end,
          request_uri = function(_, url)
            http_call_count = http_call_count + 1
            local res = http_responses[url]
            if not res then
              return nil, "connection refused"
            end
            return res, nil
          end,
        }
      end,
    }

    -- kong.cache のモック: 素通し（毎回コールバックを実行）
    _G.kong = {
      log = { debug = function() end, err = function() end, warn = function() end },
      cache = {
        get = function(_, _, _, cb, ...) return cb(...) end,
        invalidate = function() end,
      },
    }

    jwt_validator = require("kong.plugins.obo.jwt_validator")
    jwt  = require("spec.fixtures.obo.jwt")
    keys = require("spec.fixtures.obo.keys")
  end)

  teardown(function()
    _G.kong = nil
    package.loaded["resty.http"] = nil
    package.loaded["kong.plugins.obo.jwt_validator"] = nil
  end)

  before_each(function()
    http_call_count = 0
    conf = {
      identity_base_url = "https://mock-idp.example",
      tenant_id = "test-tenant",
      audience = "test-client-id",
      http_timeout = 1000,
      ssl_verify = false,
      -- issuer 省略 → identity_base_url と tenant_id から導出される
    }
    -- 正常な OpenID 設定と JWKS を返すモック（形式は docs/obo/05 のメタデータ例に準拠）
    http_responses = {
      ["https://mock-idp.example/test-tenant/v2.0/.well-known/openid-configuration"] = {
        status = 200,
        body = cjson.encode({ jwks_uri = "https://mock-idp.example/test-tenant/discovery/v2.0/keys" }),
      },
      ["https://mock-idp.example/test-tenant/discovery/v2.0/keys"] = {
        status = 200,
        body = cjson.encode({ keys = { keys.jwk() } }),
      },
    }
    -- ※ jwt.make() の既定 iss は "https://login.microsoftonline.com/test-tenant/v2.0" なので
    --   このテストでは iss を明示上書きするか conf.issuer を合わせる（下の各テスト参照）
    conf.issuer = "https://login.microsoftonline.com/test-tenant/v2.0"
  end)

  it("有効なトークンを受け入れてクレームを返す", function()
    local claims, err = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(err)
    assert.equal("test-user", claims.sub)
  end)

  it("issuer を省略すると identity_base_url と tenant_id から導出して検証する", function()
    conf.issuer = nil
    -- 導出値 https://mock-idp.example/test-tenant/v2.0 に一致する iss を持つトークン
    local token = jwt.make({ iss = "https://mock-idp.example/test-tenant/v2.0" })
    local claims = jwt_validator.validate(conf, token)
    assert.is_truthy(claims)
  end)

  it("JWT の形式が不正なら拒否する", function()
    for _, bad in ipairs({ "", "abc", "a.b", "a.b.c.d", "!!!.???.***" }) do
      local claims, err = jwt_validator.validate(conf, bad)
      assert.is_nil(claims)
      assert.is_string(err)
    end
  end)

  it("署名が改ざんされたトークンを拒否する", function()
    local token = jwt.make()
    -- ペイロード部分の末尾 1 文字を書き換えて署名を無効化する
    local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    local tampered = h .. "." .. p:sub(1, -2) .. (p:sub(-1) == "A" and "B" or "A") .. "." .. s
    local claims = jwt_validator.validate(conf, tampered)
    assert.is_nil(claims)
  end)

  it("alg が RS256 以外なら拒否する（alg confusion 対策）", function()
    local token = jwt.make(nil, { alg = "none" })
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
    -- HS256 も拒否（公開鍵を HMAC 鍵として使わせる攻撃の防止）
    token = jwt.make(nil, { alg = "HS256" })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("aud が一致しないトークンを拒否する（docs/obo/02: 他アプリ宛てトークンは拒否すべき）", function()
    local token = jwt.make({ aud = "https://graph.microsoft.com" })
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
  end)

  it("iss が一致しないトークンを拒否する", function()
    local token = jwt.make({ iss = "https://evil.example/test-tenant/v2.0" })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("期限切れ（exp が過去）のトークンを拒否する", function()
    local token = jwt.make({ exp = ngx.time() - 3600 })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("nbf が未来のトークンを拒否する", function()
    local token = jwt.make({ nbf = ngx.time() + 3600 })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("exp がない・数値でないトークンを拒否する（RFC 7523: exp は MUST）", function()
    assert.is_nil(jwt_validator.validate(conf, jwt.make({ exp = "not-a-number" })))
  end)

  it("kid がヘッダーにないトークンを拒否する", function()
    local token = jwt.make(nil, { kid = false })  -- 下の注参照
    -- 注: header_override で kid を消すには jwt.make 側で false を nil 扱いにするか、
    -- ここで自前でヘッダーを組む。実装しやすい方で良いが「kid なし → 拒否」を必ず検証すること。
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
  end)

  it("JWKS に存在しない kid のトークンを拒否する（再取得を 1 回試みた上で）", function()
    local token = jwt.make(nil, { kid = "unknown-key" })
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
  end)

  it("IdP に接続できない場合はエラーを返す", function()
    http_responses = {}  -- 全 URL で connection refused
    local claims, err = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(claims)
    assert.is_string(err)
  end)

  it("openid-configuration に jwks_uri がない場合はエラーを返す", function()
    http_responses["https://mock-idp.example/test-tenant/v2.0/.well-known/openid-configuration"].body =
      cjson.encode({ issuer = "x" })
    assert.is_nil(jwt_validator.validate(conf, jwt.make()))
  end)
end)
