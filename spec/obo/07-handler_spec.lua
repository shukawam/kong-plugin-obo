-- handler（オーケストレーション）の単体テスト
-- 下位モジュール（jwt_validator / token_exchange / token_cache）を package.loaded で
-- モックに差し替え、分岐とエラーマッピングだけを検証する

describe("obo: handler (unit)", function()
  local handler
  local conf
  -- kong.* モックが記録する状態
  local request_headers, upstream_headers, exited

  -- 各テストで挙動を差し替えるモック関数
  local mock_validate, mock_exchange, mock_cache_get

  setup(function()
    -- 下位モジュールをモックとして先に登録する（handler の require より前）
    package.loaded["kong.plugins.obo.jwt_validator"] = {
      validate = function(...) return mock_validate(...) end,
    }
    package.loaded["kong.plugins.obo.token_exchange"] = {
      exchange = function(...) return mock_exchange(...) end,
    }
    package.loaded["kong.plugins.obo.token_cache"] = {
      get = function(...) return mock_cache_get(...) end,
    }

    _G.kong = {
      log = { debug = function() end, err = function() end },
      request = {
        get_header = function(name) return request_headers[name] end,
      },
      service = {
        request = {
          set_header = function(name, value) upstream_headers[name] = value end,
        },
      },
      response = {
        -- kong.response.exit は本来リクエスト処理を打ち切る。テストでは記録するだけ
        exit = function(status, body, headers)
          exited = { status = status, body = body, headers = headers or {} }
        end,
      },
    }

    handler = require("kong.plugins.obo.handler")
  end)

  teardown(function()
    _G.kong = nil
    package.loaded["kong.plugins.obo.handler"] = nil
    package.loaded["kong.plugins.obo.jwt_validator"] = nil
    package.loaded["kong.plugins.obo.token_exchange"] = nil
    package.loaded["kong.plugins.obo.token_cache"] = nil
  end)

  before_each(function()
    request_headers, upstream_headers, exited = {}, {}, nil
    conf = { audience = "test-client-id" }
    -- 既定のモック挙動: すべて成功
    mock_validate = function() return { sub = "user" } end
    mock_cache_get = function(_, _, fn) return "exchanged-token" end
    mock_exchange = function() return { access_token = "exchanged-token", expires_in = 3600 } end
  end)

  it("成功時: Authorization を交換後トークンに差し替え、exit しない", function()
    request_headers["Authorization"] = "Bearer valid-token"
    handler:access(conf)
    assert.is_nil(exited)
    assert.equal("Bearer exchanged-token", upstream_headers["Authorization"])
  end)

  it("Authorization ヘッダーがなければ 401 + WWW-Authenticate", function()
    handler:access(conf)
    assert.equal(401, exited.status)
    assert.is_truthy(exited.headers["WWW-Authenticate"])
  end)

  it("Bearer 形式でなければ 401（Basic 認証などは対象外）", function()
    request_headers["Authorization"] = "Basic dXNlcjpwYXNz"
    handler:access(conf)
    assert.equal(401, exited.status)
  end)

  it("トークン検証失敗なら 401 + error=invalid_token、理由をレスポンスに含めない", function()
    request_headers["Authorization"] = "Bearer bad-token"
    mock_validate = function() return nil, "signature verification failed" end
    handler:access(conf)
    assert.equal(401, exited.status)
    assert.is_truthy(exited.headers["WWW-Authenticate"]:find('error="invalid_token"', 1, true))
    -- 内部の失敗理由がレスポンスボディに漏れていないこと（認証プラグインの鉄則）
    assert.is_nil(tostring(exited.body.message):find("signature", 1, true))
  end)

  it("IdP がエラーを返したら 401 + Entra のエラー識別子を WWW-Authenticate に載せる", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_cache_get = function() return nil, { status = 401, error = "interaction_required", claims = '{"x":1}' } end
    handler:access(conf)
    assert.equal(401, exited.status)
    local www = exited.headers["WWW-Authenticate"]
    assert.is_truthy(www:find('error="interaction_required"', 1, true))
    assert.is_truthy(www:find("claims=", 1, true))  -- クレームチャレンジの伝搬（docs/obo/03）
  end)

  it("IdP エラー識別子に不正な文字が含まれる場合はサニタイズされる", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_cache_get = function() return nil, { status = 401, error = 'evil", realm="pwned' } end
    handler:access(conf)
    assert.equal(401, exited.status)
    local www = exited.headers["WWW-Authenticate"]
    -- 不正な文字を含む識別子はそのまま埋め込まれない
    assert.is_nil(www:find('realm="pwned', 1, true))
    assert.is_truthy(www:find('error="invalid_token"', 1, true))
  end)

  it("IdP に接続できなければ 502", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_cache_get = function() return nil, { status = 502, error = "idp_unreachable" } end
    handler:access(conf)
    assert.equal(502, exited.status)
  end)

  it("想定外のエラーは 500", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_cache_get = function() return nil, { status = 500, error = "cache_failure" } end
    handler:access(conf)
    assert.equal(500, exited.status)
  end)

  it("token_cache.get に交換関数（token_exchange.exchange のクロージャ）を渡す", function()
    request_headers["Authorization"] = "Bearer valid-token"
    local received_fn
    mock_cache_get = function(_, _, fn) received_fn = fn; return "t" end
    handler:access(conf)
    -- 渡されたクロージャを呼ぶと exchange が実行されること
    local res = received_fn()
    assert.equal("exchanged-token", res.access_token)
  end)
end)
