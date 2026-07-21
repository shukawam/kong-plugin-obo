-- handler（オーケストレーション）の単体テスト
-- 下位モジュール（jwt_validator / token_exchange / token_cache）を package.loaded で
-- モックに差し替え、分岐とエラーマッピングだけを検証する

describe("obo: handler (unit)", function()
  local handler
  local conf
  -- kong.* モックが記録する状態
  local request_headers, upstream_headers, exited
  -- kong.log.debug に渡された引数を 1 回の呼び出しごとに連結して記録する
  -- （Issue #9: ログ無害化の検証のため、実際にログに渡された文字列を確認できるようにする）
  local debug_logs

  -- 各テストで挙動を差し替えるモック関数
  local mock_validate, mock_exchange, mock_cache_get, mock_authorize

  setup(function()
    -- 下位モジュールをモックとして先に登録する（handler の require より前）
    package.loaded["kong.plugins.obo.jwt_validator"] = {
      validate = function(...) return mock_validate(...) end,
    }
    package.loaded["kong.plugins.obo.scope_validator"] = {
      authorize = function(...) return mock_authorize(...) end,
    }
    package.loaded["kong.plugins.obo.token_exchange"] = {
      exchange = function(...) return mock_exchange(...) end,
    }
    package.loaded["kong.plugins.obo.token_cache"] = {
      get = function(...) return mock_cache_get(...) end,
    }

    _G.kong = {
      log = {
        debug = function(...)
          -- kong.log.debug は複数引数を受け取り連結してログに出す。
          -- テストでは全引数を tostring して 1 文字列にまとめ、後で検査できるようにする
          local n = select("#", ...)
          local parts = {}
          for i = 1, n do
            parts[i] = tostring(select(i, ...))
          end
          table.insert(debug_logs, table.concat(parts))
        end,
        err = function() end,
      },
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
    package.loaded["kong.plugins.obo.scope_validator"] = nil
    package.loaded["kong.plugins.obo.token_exchange"] = nil
    package.loaded["kong.plugins.obo.token_cache"] = nil
  end)

  before_each(function()
    request_headers, upstream_headers, exited = {}, {}, nil
    debug_logs = {}
    conf = { audiences = { "test-client-id" } }
    -- 既定のモック挙動: すべて成功
    mock_validate = function() return { sub = "user" } end
    mock_authorize = function() return true end
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

  -- extract_bearer_token の正規表現 "^[Bb][Ee][Aa][Rr][Ee][Rr]%s+(%S+)%s*$" の揺れ受理を、
  -- 実際に jwt_validator.validate へ渡されるトークン値を捕捉して検証する
  -- （「拒否されない」だけでなく「正しいトークンが抽出される」ことまで確認する）
  it("scheme が小文字 (bearer) でも受理し、正しいトークンを抽出する", function()
    request_headers["Authorization"] = "bearer valid-token"
    local captured_token
    mock_validate = function(_, token) captured_token = token; return { sub = "user" } end
    handler:access(conf)
    assert.is_nil(exited)
    assert.equal("valid-token", captured_token)
  end)

  it("scheme が大文字 (BEARER) でも受理し、正しいトークンを抽出する", function()
    request_headers["Authorization"] = "BEARER valid-token"
    local captured_token
    mock_validate = function(_, token) captured_token = token; return { sub = "user" } end
    handler:access(conf)
    assert.is_nil(exited)
    assert.equal("valid-token", captured_token)
  end)

  it("scheme とトークンの間に複数スペースがあっても受理し、正しいトークンを抽出する", function()
    request_headers["Authorization"] = "Bearer    valid-token"
    local captured_token
    mock_validate = function(_, token) captured_token = token; return { sub = "user" } end
    handler:access(conf)
    assert.is_nil(exited)
    assert.equal("valid-token", captured_token)
  end)

  it("トークンの後ろに末尾スペース（OWS）があっても受理し、正しいトークンを抽出する", function()
    request_headers["Authorization"] = "Bearer valid-token   "
    local captured_token
    mock_validate = function(_, token) captured_token = token; return { sub = "user" } end
    handler:access(conf)
    assert.is_nil(exited)
    assert.equal("valid-token", captured_token)
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

  it("認可失敗（scp/roles 不足）なら 403 + WWW-Authenticate error=insufficient_scope", function()
    -- 有効なトークンだが required_scopes / required_roles を満たさない場合は
    -- 認証失敗（401）ではなく「権限不足」= RFC 6750 の 403 insufficient_scope とする
    request_headers["Authorization"] = "Bearer valid-token"
    mock_authorize = function() return nil, "token is missing one or more required scopes" end
    handler:access(conf)
    assert.equal(403, exited.status)
    assert.is_truthy(exited.headers["WWW-Authenticate"]:find('error="insufficient_scope"', 1, true))
    -- 内部理由がレスポンスボディに漏れていないこと
    assert.is_nil(tostring(exited.body.message):find("scope", 1, true))
  end)

  it("認可失敗時はトークン交換を行わない（権限不足のトークンで IdP を呼ばない）", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_authorize = function() return nil, "token is missing one or more required roles" end
    local exchange_called = false
    mock_cache_get = function() exchange_called = true; return "t" end
    handler:access(conf)
    assert.equal(403, exited.status)
    assert.is_false(exchange_called)
  end)

  it("認可は検証済みクレームを受け取る（validate の戻り値が authorize に渡る）", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_validate = function() return { sub = "user", scp = "access_as_user" } end
    local received_claims
    mock_authorize = function(_, claims) received_claims = claims; return true end
    handler:access(conf)
    assert.equal("access_as_user", received_claims.scp)
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

  it("claims の値は元の JSON を正しく Base64 エンコードしたものである", function()
    request_headers["Authorization"] = "Bearer valid-token"
    local claims_json = '{"access_token":{"essential":true,"value":"X"}}'
    mock_cache_get = function()
      return nil, { status = 401, error = "interaction_required", claims = claims_json }
    end
    handler:access(conf)
    assert.equal(401, exited.status)
    local www = exited.headers["WWW-Authenticate"]
    local b64 = www:match('claims="([^"]+)"')
    assert.is_string(b64)
    -- Base64 をデコードすると、handler に渡した元の JSON 文字列と完全一致するはず
    assert.equal(claims_json, ngx.decode_base64(b64))
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

  it("設定・プロトコル起因のエラー（invalid_client）は 500 で、内部設定情報を漏らさない", function()
    -- Issue #4: invalid_client は GW のクレデンシャル設定ミス。ユーザーには汎用 500 のみ返し、
    -- error 識別子や error_description をレスポンスに含めない（debug ログのみ）
    request_headers["Authorization"] = "Bearer valid-token"
    mock_cache_get = function()
      return nil, { status = 500, error = "invalid_client",
                    detail = "AADSTS7000215: Invalid client secret provided" }
    end
    handler:access(conf)
    assert.equal(500, exited.status)
    -- WWW-Authenticate を付けない（「あなたのトークンが不正」と誤誘導しない）
    assert.is_nil(exited.headers["WWW-Authenticate"])
    -- レスポンスボディに内部の error 識別子・設定情報が漏れていないこと
    local body = tostring(exited.body.message)
    assert.is_nil(body:find("invalid_client", 1, true))
    assert.is_nil(body:find("client secret", 1, true))
    assert.is_nil(body:find("AADSTS", 1, true))
  end)

  it("レート制限/一時的なサービス不可は 503 + Retry-After 透過", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_cache_get = function()
      return nil, { status = 503, error = "temporarily_unavailable", retry_after = "30" }
    end
    handler:access(conf)
    assert.equal(503, exited.status)
    assert.equal("30", exited.headers["Retry-After"])
    -- 内部詳細を漏らさない
    assert.is_nil(tostring(exited.body.message):find("temporarily_unavailable", 1, true))
  end)

  it("503 で Retry-After が無ければヘッダーを付けない", function()
    request_headers["Authorization"] = "Bearer valid-token"
    mock_cache_get = function() return nil, { status = 503, error = "temporarily_unavailable" } end
    handler:access(conf)
    assert.equal(503, exited.status)
    assert.is_nil(exited.headers["Retry-After"])
  end)

  it("受信トークンの検証が IdP 接続失敗（JWKS 取得不可）で失敗した場合も 502", function()
    -- jwt_validator.validate の 3 番目の戻り値が truthy な場合は
    -- 「トークンが不正」（401）ではなく「IdP に到達できない」（502）
    request_headers["Authorization"] = "Bearer valid-token"
    mock_validate = function() return nil, "request to .../jwks failed: connection refused", true end
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

  -- Issue #9: IdP エラー詳細（error_description 由来の detail）の debug ログ無害化。
  -- 外部レビュー指摘により、detail は切り詰めではなく「一切ログに出さない」方針に変更
  -- （切り詰めでは先頭部分に UPN / メールアドレス等の PII が残り得るため）
  describe("ログの無害化（Issue #9）", function()
    it("token exchange 失敗時、detail（error_description 由来）はログに一切出力されない", function()
      request_headers["Authorization"] = "Bearer valid-token"
      -- error_description には PII（ここでは UPN を模した文字列）が含まれ得る
      local pii_detail = "AADSTS50079: user alice@contoso.example must enroll in MFA\r\n"
          .. "Trace ID: abc\r\nInjected-Header: evil\r\n" .. string.rep("A", 1000)
      mock_cache_get = function()
        return nil, { status = 401, error = "interaction_required", detail = pii_detail }
      end

      handler:access(conf)

      assert.equal(401, exited.status)
      for _, line in ipairs(debug_logs) do
        -- detail の内容（PII を含む断片）がどのログ行にも現れないこと
        assert.is_nil(line:find("AADSTS50079", 1, true))
        assert.is_nil(line:find("alice@contoso.example", 1, true))
        -- 念のためログインジェクション対策（CR/LF なし・常識的な長さ）も維持されていること
        assert.is_nil(line:find("\r", 1, true))
        assert.is_nil(line:find("\n", 1, true))
        assert.is_true(#line <= 512)
      end
    end)

    it("token exchange 失敗時、trace_id / correlation_id がログに含まれる", function()
      request_headers["Authorization"] = "Bearer valid-token"
      mock_cache_get = function()
        return nil, {
          status = 401,
          error = "interaction_required",
          detail = "AADSTS50079: ...",
          trace_id = "0000aaaa-11bb-cccc-dd22-eeeeee333333",
          correlation_id = "aaaa0000-bb11-2222-33cc-444444dddddd",
        }
      end

      handler:access(conf)

      local joined = table.concat(debug_logs, " | ")
      assert.is_truthy(joined:find("0000aaaa-11bb-cccc-dd22-eeeeee333333", 1, true))
      assert.is_truthy(joined:find("aaaa0000-bb11-2222-33cc-444444dddddd", 1, true))
    end)

    it("受信トークン検証エラーの理由に CR/LF が含まれてもログは無害化される", function()
      request_headers["Authorization"] = "Bearer bad-token"
      mock_validate = function()
        return nil, "signature verification failed\r\nInjected-Header: evil"
      end

      handler:access(conf)

      assert.equal(401, exited.status)
      for _, line in ipairs(debug_logs) do
        assert.is_nil(line:find("\r", 1, true))
        assert.is_nil(line:find("\n", 1, true))
      end
    end)
  end)
end)
