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

  -- token_exchange.lua:40-43: private_key_jwt 方式で client_assertion.build 自体が
  -- 失敗した場合、HTTP リクエストを送らずに status=500/client_assertion_failed を返すべき
  it("private_key_jwt で client_assertion 生成に失敗したら status=500/client_assertion_failed を返す", function()
    conf.client_auth_method = "private_key_jwt"
    conf.client_secret = nil
    conf.private_key = "not a pem"  -- pkey.new が失敗する不正な秘密鍵
    conf.certificate_thumbprint = "TEST_THUMBPRINT"

    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(500, err.status)
    assert.equal("client_assertion_failed", err.error)
    -- アサーション生成前に失敗するため、IdP への HTTP リクエストは送信されないはず
    assert.is_nil(captured)
  end)

  it("成功レスポンスをテーブルで返す", function()
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(err)
    assert.equal("exchanged-token-value", res.access_token)
    assert.equal(3269, res.expires_in)
  end)

  -- エラー分類テーブル（docs/obo/03 / RFC 6749 §5.2 で裏取り。Issue #4）
  -- ------------------------------------------------------------------
  -- ユーザー側で解決可能なエラー（再認証・再対話で解消しうる）→ 401
  -- ------------------------------------------------------------------

  it("interaction_required（4xx）は status=401 + クレームチャレンジで返す", function()
    -- 条件付きアクセス（MFA 等）。ユーザーの再対話が必要（docs/obo/03 のエラー例）
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

  it("invalid_grant（4xx）は status=401（受信トークンが無効/期限切れ/失効）", function()
    -- RFC 6749 §5.2: authorization grant（= assertion に入れた受信トークン）が
    -- invalid/expired/revoked。ユーザーが新しいトークンを取り直せば解消する → 401
    mock_res = {
      status = 400,
      body = cjson.encode({ error = "invalid_grant", error_description = "AADSTS50013: ..." }),
    }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(401, err.status)
    assert.equal("invalid_grant", err.error)
  end)

  -- ------------------------------------------------------------------
  -- ゲートウェイの設定・プロトコル起因（再認証では解消しない）→ 500
  -- ------------------------------------------------------------------

  it("invalid_client（4xx）は status=500（GW のクレデンシャル設定ミス、ユーザーのトークン起因ではない）", function()
    -- RFC 6749 §5.2: 「Client authentication failed」= プラグイン自身の
    -- client_secret / client_assertion の設定不備。ユーザーに 401 を返すと
    -- 「あなたのトークンが不正」と誤誘導し、内部の設定不備を外部に示唆する → 500
    mock_res = {
      status = 401,
      body = cjson.encode({ error = "invalid_client", error_description = "AADSTS7000215: Invalid client secret" }),
    }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(500, err.status)
    assert.is_nil(err.claims)  -- 設定エラーではクレームチャレンジを載せない
  end)

  it("unauthorized_client（4xx）は status=500（この grant_type を許可されていない設定）", function()
    mock_res = {
      status = 400,
      body = cjson.encode({ error = "unauthorized_client" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(500, err.status)
  end)

  it("invalid_scope（4xx）は status=500（conf.scopes の設定ミス）", function()
    mock_res = {
      status = 400,
      body = cjson.encode({ error = "invalid_scope" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(500, err.status)
  end)

  it("unsupported_grant_type（4xx）は status=500（プロトコル/設定）", function()
    mock_res = {
      status = 400,
      body = cjson.encode({ error = "unsupported_grant_type" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(500, err.status)
  end)

  it("invalid_request（4xx）は status=500（リクエスト構築の問題）", function()
    mock_res = {
      status = 400,
      body = cjson.encode({ error = "invalid_request" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(500, err.status)
  end)

  it("許可リストにない未知の error は status=500（ユーザーのトークンを不当に不正扱いしない）", function()
    mock_res = {
      status = 400,
      body = cjson.encode({ error = "some_future_unknown_error" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(500, err.status)
  end)

  -- ------------------------------------------------------------------
  -- 一時的にサービス利用不可 → 503 + Retry-After
  -- ------------------------------------------------------------------

  it("HTTP 429 は status=503 + Retry-After 透過（body の error に依らない）", function()
    -- レート制限。Entra が付けた Retry-After（delta-seconds）を透過する
    mock_res = {
      status = 429,
      headers = { ["Retry-After"] = "30" },
      body = cjson.encode({ error = "temporarily_unavailable" }),
    }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal(503, err.status)
    assert.equal("30", err.retry_after)
  end)

  it("HTTP 429 で Retry-After ヘッダーが無ければ retry_after は nil", function()
    mock_res = { status = 429, body = cjson.encode({ error = "rate_limited" }) }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(503, err.status)
    assert.is_nil(err.retry_after)
  end)

  it("Retry-After が数字以外なら透過しない（ヘッダーインジェクション防止）", function()
    mock_res = {
      status = 429,
      headers = { ["Retry-After"] = 'evil"\r\nSet-Cookie: x' },
      body = cjson.encode({ error = "temporarily_unavailable" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(503, err.status)
    assert.is_nil(err.retry_after)
  end)

  it("temporarily_unavailable（4xx body）は status=503", function()
    -- RFC 6749 §4.1.2.1: 「一時的な過負荷またはメンテナンス」。再試行で解消しうる
    mock_res = {
      status = 400,
      headers = { ["Retry-After"] = "5" },
      body = cjson.encode({ error = "temporarily_unavailable" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(503, err.status)
    assert.equal("5", err.retry_after)
  end)

  it("HTTP 5xx でもボディが temporarily_unavailable なら status=503 + Retry-After", function()
    -- Entra 自身が一時的サービス不可を返す最も典型的な形（HTTP 503 + エラー JSON）。
    -- 有効な Entra エラー JSON はプロキシ由来ではなく Entra 自身の応答である証拠なので、
    -- HTTP 5xx でも error 文字列の分類（503 + Retry-After 透過）を優先する
    mock_res = {
      status = 503,
      headers = { ["Retry-After"] = "120" },
      body = cjson.encode({ error = "temporarily_unavailable" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(503, err.status)
    assert.equal("120", err.retry_after)
  end)

  -- ------------------------------------------------------------------
  -- IdP 側の障害 → 502
  -- ------------------------------------------------------------------

  it("error フィールドのない HTTP 5xx は status=502（IdP 側障害）", function()
    -- Entra のエラー JSON でない 5xx（ゲートウェイ/プロキシ由来など）は IdP 側障害として 502
    mock_res = {
      status = 503,
      body = cjson.encode({ message = "upstream connect error" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(502, err.status)
  end)

  it("HTTP 5xx で error が temporarily_unavailable 以外なら status=502", function()
    -- server_error 等の 5xx エラー JSON は IdP 側障害として 502。
    -- 401（ユーザー起因）/ 500（設定起因）の分類は 4xx にのみ適用する
    mock_res = {
      status = 500,
      body = cjson.encode({ error = "server_error" }),
    }
    local _, err = token_exchange.exchange(conf, "t")
    assert.equal(502, err.status)
  end)

  -- ------------------------------------------------------------------
  -- 追跡用 ID の伝搬（Issue #9）
  -- ------------------------------------------------------------------

  it("Entra のエラー JSON に trace_id / correlation_id があれば err テーブルに載せる（Issue #9）", function()
    -- error_description をそのままログに出さなくても、サポート問い合わせに必要な
    -- 追跡用 ID をログで確認できるようにするための伝搬（詳細は docs/obo/03 のエラー例）
    mock_res = {
      status = 400,
      body = cjson.encode({
        error = "interaction_required",
        error_description = "AADSTS50079: ...\r\nTrace ID: 0000aaaa-11bb-cccc-dd22-eeeeee333333",
        error_codes = { 50079 },
        timestamp = "2017-05-01 22:43:20Z",
        trace_id = "0000aaaa-11bb-cccc-dd22-eeeeee333333",
        correlation_id = "aaaa0000-bb11-2222-33cc-444444dddddd",
      }),
    }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.equal("0000aaaa-11bb-cccc-dd22-eeeeee333333", err.trace_id)
    assert.equal("aaaa0000-bb11-2222-33cc-444444dddddd", err.correlation_id)
  end)

  it("trace_id / correlation_id が無い場合は err に含まれない", function()
    mock_res = {
      status = 400,
      body = cjson.encode({
        error = "invalid_grant",
        error_description = "some description",
      }),
    }
    local res, err = token_exchange.exchange(conf, "t")
    assert.is_nil(res)
    assert.is_nil(err.trace_id)
    assert.is_nil(err.correlation_id)
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
