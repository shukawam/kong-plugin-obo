-- 統合テスト: 実際の Kong を起動し、モック IdP（nginx.template 内の server）を経由して
-- プラグイン全体の振る舞いを end-to-end で検証する
-- シナリオ一覧は kong-plugin-test-patterns スキル参照

local helpers = require "spec.helpers"
local jwt = require "spec.fixtures.obo.jwt"

local PLUGIN_NAME = "obo"
local MOCK_IDP = "http://127.0.0.1:10999"

for _, strategy in helpers.all_strategies() do if strategy ~= "cassandra" then
  describe(PLUGIN_NAME .. ": (integration) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

      -- 正常系ルート: モック IdP に向けた設定
      local route1 = bp.routes:insert({ hosts = { "obo.example" } })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = {
          tenant_id = "test-tenant",
          client_id = "test-client-id",
          client_secret = "test-secret",
          scopes = { "api://downstream/.default" },
          audience = "test-client-id",
          -- jwt.make() の既定 iss に合わせる
          issuer = "https://login.microsoftonline.com/test-tenant/v2.0",
          identity_base_url = MOCK_IDP,
          ssl_verify = false,
        },
      }

      -- IdP ダウン系ルート: 誰も listen していないポートに向ける
      local route2 = bp.routes:insert({ hosts = { "obo-down.example" } })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route2.id },
        config = {
          tenant_id = "test-tenant",
          client_id = "test-client-id",
          client_secret = "test-secret",
          scopes = { "api://downstream/.default" },
          audience = "test-client-id",
          issuer = "https://login.microsoftonline.com/test-tenant/v2.0",
          identity_base_url = "http://127.0.0.1:10998",  -- モック IdP とは別の閉じたポート
          ssl_verify = false,
        },
      }

      -- 認可（required_scopes）系ルート: scp に access_as_user を要求する
      local route3 = bp.routes:insert({ hosts = { "obo-scoped.example" } })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route3.id },
        config = {
          tenant_id = "test-tenant",
          client_id = "test-client-id",
          client_secret = "test-secret",
          scopes = { "api://downstream/.default" },
          audience = "test-client-id",
          issuer = "https://login.microsoftonline.com/test-tenant/v2.0",
          identity_base_url = MOCK_IDP,
          ssl_verify = false,
          required_scopes = { "access_as_user" },
        },
      }

      assert(helpers.start_kong({
        database = strategy,
        -- モック IdP を含む自前テンプレートを使う
        -- 注意: pongo コンテナ内では busted の cwd が /kong（Kong 本体のソース）になり、
        -- リポジトリは /kong-plugin にマウントされる。相対パスは /kong 基準で解決されて
        -- 失敗するため、絶対パスを使う。
        nginx_conf = "/kong-plugin/spec/fixtures/obo/nginx.template",
        plugins = "bundled," .. PLUGIN_NAME,
        declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)

    it("有効なトークン: Authorization が交換後トークンに差し替わり 200", function()
      local r = client:get("/request", {
        headers = { host = "obo.example", authorization = "Bearer " .. jwt.make() },
      })
      assert.response(r).has.status(200)
      -- モックバックエンドにエコーされたリクエストヘッダーを検証する
      local auth = assert.request(r).has.header("authorization")
      assert.equal("Bearer mock-exchanged-token", auth)
    end)

    it("Authorization ヘッダーなし: 401 + WWW-Authenticate", function()
      local r = client:get("/request", { headers = { host = "obo.example" } })
      assert.response(r).has.status(401)
      assert.response(r).has.header("WWW-Authenticate")
    end)

    it("署名が不正なトークン: 401", function()
      local token = jwt.make()
      local tampered = token:sub(1, -3) .. "xx"  -- 署名部分を壊す
      local r = client:get("/request", {
        headers = { host = "obo.example", authorization = "Bearer " .. tampered },
      })
      assert.response(r).has.status(401)
    end)

    it("aud 不一致のトークン: 401（IdP に送らずプラグインが拒否）", function()
      local r = client:get("/request", {
        headers = { host = "obo.example",
                    authorization = "Bearer " .. jwt.make({ aud = "someone-else" }) },
      })
      assert.response(r).has.status(401)
    end)

    it("期限切れトークン: 401", function()
      local r = client:get("/request", {
        headers = { host = "obo.example",
                    authorization = "Bearer " .. jwt.make({ exp = ngx.time() - 3600 }) },
      })
      assert.response(r).has.status(401)
    end)

    it("IdP がエラー JSON を返す: 401 + WWW-Authenticate にエラー識別子", function()
      -- モック IdP は scenario=idp_error クレームを持つ assertion にエラーを返す
      local r = client:get("/request", {
        headers = { host = "obo.example",
                    authorization = "Bearer " .. jwt.make({ scenario = "idp_error" }) },
      })
      assert.response(r).has.status(401)
      local www = assert.response(r).has.header("WWW-Authenticate")
      assert.is_truthy(www:find("interaction_required", 1, true))
    end)

    it("required_scopes を満たすトークン（scp 一致）: 200 で交換される", function()
      local token = jwt.make({ scp = "access_as_user Mail.Read", sub = "scoped-ok-user" })
      local r = client:get("/request", {
        headers = { host = "obo-scoped.example", authorization = "Bearer " .. token },
      })
      assert.response(r).has.status(200)
      local auth = assert.request(r).has.header("authorization")
      assert.equal("Bearer mock-exchanged-token", auth)
    end)

    it("required_scopes 不足（scp クレームなし）: 403 + insufficient_scope（IdP に送らない）", function()
      -- jwt.make() の既定トークンには scp が無い（＝ app-only 相当）。
      -- 有効な署名・aud だが権限不足なので 401 ではなく 403 insufficient_scope で拒否する。
      -- 権限不足のトークンでトークン交換（IdP 呼び出し）が発生しないことも、
      -- モック IdP のトークンエンドポイント呼び出し回数カウンタ（/_calls）で検証する
      local http = require "resty.http"
      local function token_calls()
        local c = assert(http.new())
        local res = assert(c:request_uri(MOCK_IDP .. "/_calls"))
        return tonumber(res.body:match("%d+"))
      end

      local before = token_calls()
      local r = client:get("/request", {
        headers = { host = "obo-scoped.example", authorization = "Bearer " .. jwt.make() },
      })
      assert.response(r).has.status(403)
      local www = assert.response(r).has.header("WWW-Authenticate")
      assert.is_truthy(www:find('error="insufficient_scope"', 1, true))
      -- 403 の間、トークンエンドポイントは一度も呼ばれていないこと
      assert.equal(before, token_calls())
    end)

    it("IdP に接続できない: 502", function()
      local r = client:get("/request", {
        headers = { host = "obo-down.example", authorization = "Bearer " .. jwt.make() },
      })
      assert.response(r).has.status(502)
    end)

    it("同じトークンの 2 回目はキャッシュから返る（IdP の呼び出し回数が増えない）", function()
      -- sub を変えて他テストとキャッシュが混ざらないようにする
      local token = jwt.make({ sub = "cache-test-user" })
      local http = require "resty.http"

      -- 呼び出し回数カウンタを読むローカル関数
      local function token_calls()
        local c = assert(http.new())
        local res = assert(c:request_uri(MOCK_IDP .. "/_calls"))
        return tonumber(res.body:match("%d+"))
      end

      local before = token_calls()
      for _ = 1, 2 do
        local r = client:get("/request", {
          headers = { host = "obo.example", authorization = "Bearer " .. token },
        })
        assert.response(r).has.status(200)
        client:close()
        client = helpers.proxy_client()
      end
      assert.equal(before + 1, token_calls())  -- 2 リクエストで交換は 1 回だけ
    end)

  end)
end end
