-- スキーマ（プラグイン設定のバリデーション）のテスト
-- 認証プラグインでは「誤設定が拒否されること」が正常系と同じくらい重要

local PLUGIN_NAME = "obo"

-- spec.helpers のスキーマ検証ヘルパーで設定を検証する関数を用意
local validate do
  local validate_entity = require("spec.helpers").validate_plugin_config_schema
  local plugin_schema = require("kong.plugins."..PLUGIN_NAME..".schema")
  function validate(data)
    return validate_entity(data, plugin_schema)
  end
end

-- テストで使い回す有効な最小設定を返す（各テストで一部だけ書き換える）
local function base_config()
  return {
    tenant_id = "11111111-2222-3333-4444-555555555555",
    client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    client_secret = "test-secret",
    scopes = { "https://graph.microsoft.com/.default" },
    audience = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  }
end

describe(PLUGIN_NAME .. ": (schema)", function()

  it("有効な最小設定（client_secret 方式）を受け入れる", function()
    local ok, err = validate(base_config())
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("既定値が設定される", function()
    local ok = validate(base_config())
    local conf = ok.config
    assert.equal("client_secret", conf.client_auth_method)
    assert.equal("https://login.microsoftonline.com", conf.identity_base_url)
    assert.is_true(conf.token_cache_enabled)
    assert.equal(30, conf.cache_ttl_margin)
    assert.equal(10000, conf.http_timeout)
    assert.is_true(conf.ssl_verify)
  end)

  it("tenant_id がないと拒否する", function()
    local config = base_config()
    config.tenant_id = nil
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err.config.tenant_id)
  end)

  it("client_id がないと拒否する", function()
    local config = base_config()
    config.client_id = nil
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err.config.client_id)
  end)

  it("scopes が空配列だと拒否する", function()
    local config = base_config()
    config.scopes = {}
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err.config.scopes)
  end)

  it("audience がないと拒否する", function()
    local config = base_config()
    config.audience = nil
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err.config.audience)
  end)

  it("client_auth_method=client_secret で client_secret がないと拒否する", function()
    local config = base_config()
    config.client_secret = nil
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err)  -- conditional entity_check のエラー
  end)

  it("client_auth_method=private_key_jwt で private_key がないと拒否する", function()
    local config = base_config()
    config.client_auth_method = "private_key_jwt"
    config.client_secret = nil
    config.certificate_thumbprint = "abc"
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err)
  end)

  it("client_auth_method=private_key_jwt で certificate_thumbprint がないと拒否する", function()
    local config = base_config()
    config.client_auth_method = "private_key_jwt"
    config.client_secret = nil
    config.private_key = "-----BEGIN PRIVATE KEY-----..."
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err)
  end)

  it("private_key_jwt 方式の有効な設定を受け入れる", function()
    local config = base_config()
    config.client_auth_method = "private_key_jwt"
    config.client_secret = nil
    config.private_key = "-----BEGIN PRIVATE KEY-----..."
    config.certificate_thumbprint = "l3-TluOZ2SweEuNRWQ0QMTf4WBHUdEQGz1_hCMS-EFA"
    local ok, err = validate(config)
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("client_auth_method に不明な値を指定すると拒否する", function()
    local config = base_config()
    config.client_auth_method = "mtls"
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err.config.client_auth_method)
  end)

  it("cache_ttl_margin に負の値を指定すると拒否する", function()
    local config = base_config()
    config.cache_ttl_margin = -1
    local ok, err = validate(config)
    assert.is_falsy(ok)
    assert.is_truthy(err.config.cache_ttl_margin)
  end)

end)
