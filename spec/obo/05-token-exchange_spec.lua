-- OBO トークン交換のテスト
-- 仕様: docs/obo/02-token-request.md（リクエスト）, docs/obo/03-token-response.md（レスポンス）
-- resty.http をモックし、送信されるパラメータと、レスポンスの解釈を検証する

local cjson = require "cjson.safe"

describe("obo: token_exchange (unit)", function()
  local token_exchange, keys
  local conf
  local captured   -- 直近のリクエスト内容（url, params）を捕捉する
  local mock_res   -- モックが返すレスポンス（各テストで設定）
  local mock_err   -- 接続エラーを模擬する場合に設定

  setup(function()
    package.loaded["resty.http"] = {
      new = function()
        return {
          set_timeout = function() end,
          request_uri = function(_, url, params)
            captured = { url = url, params = params }
            if mock_err then return nil, mock_err end
            return mock_res, nil
          end,
        }
      end,
    }
    _G.kong = { log = { debug = function() end, err = function() end } }
    token_exchange = require("kong.plugins.obo.token_exchange")
    keys = require("spec.fixtures.obo.keys")
  end)

  teardown(function()
    _G.kong = nil
    package.loaded["resty.http"] = nil
    package.loaded["kong.plugins.obo.token_exchange"] = nil
  end)

  before_each(function()
    captured, mock_err = nil, nil
    mock_res = {
      status = 200,
      body = cjson.encode({
        token_type = "Bearer",
        scope = "https://downstream.example/.default",
        expires_in = 3269,
        access_token = "exchanged-token-value",
      }),
    }
    conf = {
      identity_base_url = "https://login.microsoftonline.com",
      tenant_id = "test-tenant",
      client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      client_auth_method = "client_secret",
      client_secret = "test-secret",
      scopes = { "https://downstream.example/.default" },
      http_timeout = 1000,
      ssl_verify = true,
    }
  end)

  -- application/x-www-form-urlencoded のボディをテーブルに戻すテスト用ローカル関数
  local function decode_body()
    return ngx.decode_args(captured.params.body)
  end

  it("トークンエンドポイント URL を正しく組み立てる", function()
    assert.equal("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
                 token_exchange.token_endpoint(conf))
  end)

  it("client_secret 方式で必須パラメータをすべて送る（docs/obo/02 ケース1）", function()
    assert(token_exchange.exchange(conf, "incoming-token"))
    assert.equal("https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token", captured.url)
    assert.equal("POST", captured.params.method)
    assert.equal("application/x-www-form-urlencoded", captured.params.headers["Content-Type"])

    local body = decode_body()
    assert.equal("urn:ietf:params:oauth:grant-type:jwt-bearer", body.grant_type)
    assert.equal(conf.client_id, body.client_id)
    assert.equal("test-secret", body.client_secret)
    assert.equal("incoming-token", body.assertion)
    assert.equal("https://downstream.example/.default", body.scope)
    assert.equal("on_behalf_of", body.requested_token_use)
  end)

  it("scopes が複数ならスペース区切りで連結する", function()
    conf.scopes = { "api://x/scope1", "api://x/scope2" }
    assert(token_exchange.exchange(conf, "t"))
    assert.equal("api://x/scope1 api://x/scope2", decode_body().scope)
  end)

  it("private_key_jwt 方式では client_assertion を送り client_secret を送らない（docs/obo/02 ケース2）", function()
    conf.client_auth_method = "private_key_jwt"
    conf.client_secret = nil
    conf.private_key = keys.private_pem
    conf.certificate_thumbprint = "TEST_THUMBPRINT"

    assert(token_exchange.exchange(conf, "t"))
    local body = decode_body()
    assert.is_nil(body.client_secret)
    assert.equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", body.client_assertion_type)
    -- client_assertion は JWT 形式（3 パート）であること
    assert.is_truthy(body.client_assertion:match("^[^.]+%.[^.]+%.[^.]+$"))
  end)

  it("成功レスポンスをテーブルで返す", function()
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(err)
    assert.equal("exchanged-token-value", res.access_token)
    assert.equal(3269, res.expires_in)
  end)

  it("Entra のエラー JSON（4xx）は status=401 のエラーとして返す", function()
    mock_res = {
      status = 400,
      body = cjson.encode({
        error = "interaction_required",
        error_description = "AADSTS50079: ...",
        claims = '{"access_token":{...}}',
      }),
    }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(401, err.status)
    assert.equal("interaction_required", err.error)
    assert.is_string(err.claims)  -- クレームチャレンジは handler が WWW-Authenticate に載せる
  end)

  it("接続失敗は status=502 のエラーとして返す", function()
    mock_err = "connection refused"
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(502, err.status)
  end)

  it("200 でも access_token がなければエラーとして返す", function()
    mock_res = { status = 200, body = cjson.encode({ token_type = "Bearer" }) }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(502, err.status)
  end)

  it("JSON でないレスポンスは status=502 のエラーとして返す", function()
    mock_res = { status = 502, body = "<html>Bad Gateway</html>" }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(502, err.status)
  end)
end)
