-- 統合テスト: 実際の Kong を起動し、モック IdP（nginx.template 内の server）を経由して
-- プラグイン全体の振る舞いを end-to-end で検証する
-- シナリオ一覧は kong-plugin-test-patterns スキル参照

local helpers = require "spec.helpers"
local jwt = require "spec.fixtures.obo.jwt"
local keys = require "spec.fixtures.obo.keys"

local PLUGIN_NAME = "obo"
local MOCK_IDP = "http://127.0.0.1:10999"
-- スキーマの tenant_id 制約（GUID）に合わせる
local TENANT_ID = "11111111-1111-1111-1111-111111111111"
-- モック IdP のトークンエンドポイント（direct probe で使う）
local MOCK_TOKEN_URL = MOCK_IDP .. "/" .. TENANT_ID .. "/oauth2/v2.0/token"
-- モック IdP のメタデータが自己申告する issuer（{identity_base_url}/{tenant}/v2.0）。
-- 受信トークンの iss は常にメタデータの issuer と完全一致を要求されるため、
-- テストトークンの iss を既定でこれに合わせる
local MOCK_ISSUER = MOCK_IDP .. "/" .. TENANT_ID .. "/v2.0"
-- モック IdP の v1.0 メタデータが自己申告する issuer（{base}/{tenant}/ 末尾スラッシュ付き）。
-- 実 Entra では https://sts.windows.net/{tid}/ だが、プラグインの検証はホスト固定ではなく
-- 「テナント GUID の一致」なのでモックホストで表す
local MOCK_V1_ISSUER = MOCK_IDP .. "/" .. TENANT_ID .. "/"

-- 既定でモックのメタデータ issuer に一致する iss を持つテスト JWT を作るローカル関数
local function make_token(claims_override)
  claims_override = claims_override or {}
  if claims_override.iss == nil then
    claims_override.iss = MOCK_ISSUER
  end
  return jwt.make(claims_override)
end

-- JWT の署名部を「決定的に」壊すローカル関数。
-- 以前の「末尾 2 文字を "xx" に置換する」方式は、署名がたまたま "xx" で終わると
-- 改ざんが no-op になり（確率 ~1/4096）、テストが 200 を返して落ちるフレークがあった。
-- また base64url の末尾 1 文字はパディングビットを含むため、末尾だけを変えても
-- デコード後のバイト列が変わらないことがある。そこで署名セグメントの「先頭」1 文字を
-- 現在の文字と必ず異なる文字（A でなければ A、A なら B）に置き換える。
-- 先頭文字の 6 ビットは必ずデコード結果の第 1 バイトに寄与するので署名バイト列が確実に
-- 変わり、置換文字も base64url アルファベット内なので改ざん後も base64url として妥当なまま
local function tamper_signature(token)
  local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
  assert(s, "not a JWT: " .. tostring(token))
  local first = s:sub(1, 1)
  local replaced = (first == "A") and "B" or "A"
  return h .. "." .. p .. "." .. replaced .. s:sub(2)
end

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
          tenant_id = TENANT_ID,
          client_id = "test-client-id",
          client_secret = "test-secret",
          scopes = { "api://downstream/.default" },
          audiences = { "test-client-id" },
          -- issuer（ピン）は未設定: メタデータの issuer が唯一の期待値になる
          identity_base_url = MOCK_IDP,
          ssl_verify = false,
        },
      }

      -- private_key_jwt 系ルート: client assertion でクライアント認証する（docs/obo/04）
      local route3 = bp.routes:insert({ hosts = { "obo-pkjwt.example" } })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route3.id },
        config = {
          tenant_id = TENANT_ID,
          client_id = "test-client-id",
          -- client_secret ではなく秘密鍵署名の client assertion を使う
          client_auth_method = "private_key_jwt",
          private_key = keys.private_pem,               -- テスト用 RSA 秘密鍵（署名に使う）
          certificate_thumbprint = "test-thumbprint",   -- x5t#S256 に入るダミー値
          scopes = { "api://downstream/.default" },
          audiences = { "test-client-id" },
          -- issuer（ピン）は未設定: メタデータの issuer が唯一の期待値になる
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
          tenant_id = TENANT_ID,
          client_id = "test-client-id",
          client_secret = "test-secret",
          scopes = { "api://downstream/.default" },
          audiences = { "test-client-id" },
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
          tenant_id = TENANT_ID,
          client_id = "test-client-id",
          client_secret = "test-secret",
          scopes = { "api://downstream/.default" },
          audiences = { "test-client-id" },
          -- issuer（ピン）は未設定: メタデータの issuer が唯一の期待値になる
          identity_base_url = MOCK_IDP,
          ssl_verify = false,
          required_scopes = { "access_as_user" },
        },
      }

      -- v1.0 トークン受理ルート: allow_v1_tokens を有効にし、aud は両形式を許容する
      local route5 = bp.routes:insert({ hosts = { "obo-v1.example" } })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route5.id },
        config = {
          tenant_id = TENANT_ID,
          client_id = "test-client-id",
          client_secret = "test-secret",
          scopes = { "api://downstream/.default" },
          audiences = { "test-client-id", "api://test-client-id" },
          allow_v1_tokens = true,
          identity_base_url = MOCK_IDP,
          ssl_verify = false,
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
        headers = { host = "obo.example", authorization = "Bearer " .. make_token() },
      })
      assert.response(r).has.status(200)
      -- モックバックエンドにエコーされたリクエストヘッダーを検証する
      local auth = assert.request(r).has.header("authorization")
      assert.equal("Bearer mock-exchanged-token", auth)
    end)

    it("private_key_jwt ルート: Authorization が交換後トークンに差し替わり 200", function()
      -- プラグインが署名する client assertion をモック IdP が厳格検証（type/aud/署名/
      -- client_secret 非同送）した上で 200 を返すため、この成功はアサーションが実際に
      -- 正しく組まれていることの e2e 証拠になる
      local r = client:get("/request", {
        headers = { host = "obo-pkjwt.example", authorization = "Bearer " .. make_token() },
      })
      assert.response(r).has.status(200)
      local auth = assert.request(r).has.header("authorization")
      assert.equal("Bearer mock-exchanged-token", auth)
    end)

    -- ------------------------------------------------------------------
    -- モック IdP の client assertion 検証（issue-6）を直接叩くテスト群。
    -- プラグイン経由では常に正しい assertion しか送られないため、モックが「違反を
    -- 実際に 400 で弾く」ことはトークンエンドポイントを直接叩いて確認する。
    -- これによりモックの検証が偶発 pass（存在チェックだけ）でないことを保証する。
    -- ------------------------------------------------------------------
    local http = require "resty.http"

    -- モック IdP のトークンエンドポイントに form-urlencoded で POST するローカル関数
    local function post_token(body)
      local c = assert(http.new())
      return assert(c:request_uri(MOCK_TOKEN_URL, {
        method = "POST",
        body = ngx.encode_args(body),
        headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
      }))
    end

    -- private_key_jwt フローの「正しい」リクエストボディを作るローカル関数。
    -- overrides で個別フィールドを崩す（値に false を渡すとそのキーを削除する）
    local function pkjwt_body(overrides)
      local body = {
        grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer",
        requested_token_use = "on_behalf_of",
        assertion = jwt.make(),  -- 受信ユーザートークン相当（存在すれば第 1 ゲートを通る）
        client_id = "test-client-id",
        scope = "api://downstream/.default",
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion = jwt.make_assertion(),
      }
      for k, v in pairs(overrides or {}) do
        if v == false then body[k] = nil else body[k] = v end
      end
      return body
    end

    it("モック IdP: 正しい client assertion は 200 で受理される", function()
      local res = post_token(pkjwt_body())
      assert.equal(200, res.status)
      assert.is_truthy(res.body:find("mock-exchanged-token", 1, true))
    end)

    it("モック IdP: client_assertion_type が不正だと 400", function()
      local res = post_token(pkjwt_body({ client_assertion_type = "urn:wrong" }))
      assert.equal(400, res.status)
      -- 意図したチェック（type 検証）で弾かれたことを error_description で自己診断する
      assert.is_truthy(res.body:find("bad client_assertion_type", 1, true))
    end)

    it("モック IdP: client_assertion の aud が不一致だと 400", function()
      local res = post_token(pkjwt_body({
        client_assertion = jwt.make_assertion({ aud = "https://login.microsoftonline.com/other/oauth2/v2.0/token" }),
      }))
      assert.equal(400, res.status)
      assert.is_truthy(res.body:find("aud mismatch", 1, true))
    end)

    it("モック IdP: client_assertion の署名が壊れていると 400", function()
      local assertion = jwt.make_assertion()
      -- 署名部を決定的に書き換えて PS256 検証を失敗させる（tamper_signature のコメント参照）
      local tampered = tamper_signature(assertion)
      local res = post_token(pkjwt_body({ client_assertion = tampered }))
      assert.equal(400, res.status)
      assert.is_truthy(res.body:find("signature invalid", 1, true))
    end)

    it("モック IdP: PKCS#1 v1.5 パディングで署名した client_assertion は 400", function()
      -- PSS パディング強制の直接証明。jwt.make は pk:sign(input, "sha256")（パディング
      -- 引数なし = PKCS#1 v1.5 パディング）で署名するため、クレームだけ正しい assertion を
      -- 作って送ると「署名パディングの違いだけ」で弾かれるはず。
      -- もしこれが 200 になる場合、lua-resty-openssl がパディング引数を無視して
      -- sign/verify 双方が PKCS#1 v1.5 に落ちている（実質 RS256 化）ことを意味する。
      local pkcs1_assertion = jwt.make({
        aud = MOCK_TOKEN_URL,   -- aud 検証は通る値にして、署名検証だけを失敗させる
        iss = "test-client-id",
        sub = "test-client-id",
      })
      local res = post_token(pkjwt_body({ client_assertion = pkcs1_assertion }))
      assert.equal(400, res.status)
      assert.is_truthy(res.body:find("signature invalid", 1, true))
    end)

    it("モック IdP: client_assertion と一緒に client_secret を送ると 400", function()
      local res = post_token(pkjwt_body({ client_secret = "must-not-be-sent" }))
      assert.equal(400, res.status)
      assert.is_truthy(res.body:find("client_secret must not accompany", 1, true))
    end)

    it("Authorization ヘッダーなし: 401 + WWW-Authenticate", function()
      local r = client:get("/request", { headers = { host = "obo.example" } })
      assert.response(r).has.status(401)
      assert.response(r).has.header("WWW-Authenticate")
    end)

    it("署名が不正なトークン: 401", function()
      local token = make_token()
      local tampered = tamper_signature(token)  -- 署名部分を決定的に壊す
      local r = client:get("/request", {
        headers = { host = "obo.example", authorization = "Bearer " .. tampered },
      })
      assert.response(r).has.status(401)
    end)

    it("aud 不一致のトークン: 401（IdP に送らずプラグインが拒否）", function()
      local r = client:get("/request", {
        headers = { host = "obo.example",
                    authorization = "Bearer " .. make_token({ aud = "someone-else" }) },
      })
      assert.response(r).has.status(401)
    end)

    it("期限切れトークン: 401", function()
      local r = client:get("/request", {
        headers = { host = "obo.example",
                    authorization = "Bearer " .. make_token({ exp = ngx.time() - 3600 }) },
      })
      assert.response(r).has.status(401)
    end)

    it("IdP がエラー JSON を返す: 401 + WWW-Authenticate にエラー識別子", function()
      -- モック IdP は scenario=idp_error クレームを持つ assertion にエラーを返す
      local r = client:get("/request", {
        headers = { host = "obo.example",
                    authorization = "Bearer " .. make_token({ scenario = "idp_error" }) },
      })
      assert.response(r).has.status(401)
      local www = assert.response(r).has.header("WWW-Authenticate")
      assert.is_truthy(www:find("interaction_required", 1, true))
    end)

    it("required_scopes を満たすトークン（scp 一致）: 200 で交換される", function()
      local token = make_token({ scp = "access_as_user Mail.Read", sub = "scoped-ok-user" })
      local r = client:get("/request", {
        headers = { host = "obo-scoped.example", authorization = "Bearer " .. token },
      })
      assert.response(r).has.status(200)
      local auth = assert.request(r).has.header("authorization")
      assert.equal("Bearer mock-exchanged-token", auth)
    end)

    it("required_scopes 不足（scp クレームなし）: 403 + insufficient_scope（IdP に送らない）", function()
      -- scp を持たないトークン（＝ app-only 相当）。有効な署名・aud だが権限不足なので
      -- 401 ではなく 403 insufficient_scope で拒否する。
      -- 権限不足のトークンでトークン交換（IdP 呼び出し）が発生しないことも、
      -- モック IdP のトークンエンドポイント呼び出し回数カウンタ（/_calls）で検証する。
      -- sub を固有化する理由: token_cache のキーはトークン文字列由来のため、既定の
      -- jwt.make() だと同一秒に生成された先行テストのトークンと完全一致し、
      -- 「呼び出し回数が増えない」がキャッシュヒットで偶然成立してしまう可能性がある
      local token = make_token({ sub = "scoped-denied-user" })
      local http = require "resty.http"
      local function token_calls()
        local c = assert(http.new())
        local res = assert(c:request_uri(MOCK_IDP .. "/_calls"))
        return tonumber(res.body:match("%d+"))
      end

      local before = token_calls()
      local r = client:get("/request", {
        headers = { host = "obo-scoped.example", authorization = "Bearer " .. token },
      })
      assert.response(r).has.status(403)
      local www = assert.response(r).has.header("WWW-Authenticate")
      assert.is_truthy(www:find('error="insufficient_scope"', 1, true))
      -- 403 の間、トークンエンドポイントは一度も呼ばれていないこと
      assert.equal(before, token_calls())
    end)

    it("IdP に接続できない: 502", function()
      local r = client:get("/request", {
        headers = { host = "obo-down.example", authorization = "Bearer " .. make_token() },
      })
      assert.response(r).has.status(502)
    end)

    it("同じトークンの 2 回目はキャッシュから返る（IdP の呼び出し回数が増えない）", function()
      -- sub を変えて他テストとキャッシュが混ざらないようにする
      local token = make_token({ sub = "cache-test-user" })
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

    it("v1.0 トークン（allow_v1_tokens ルート）: 200 で交換される", function()
      -- ver = "1.0"・iss 末尾スラッシュ・aud は App ID URI 形式という v1.0 の典型形
      local token = jwt.make({ ver = "1.0", iss = MOCK_V1_ISSUER,
                               aud = "api://test-client-id", sub = "v1-user" })
      local r = client:get("/request", {
        headers = { host = "obo-v1.example", authorization = "Bearer " .. token },
      })
      assert.response(r).has.status(200)
      local auth = assert.request(r).has.header("authorization")
      assert.equal("Bearer mock-exchanged-token", auth)
    end)

    it("v2.0 トークンも allow_v1_tokens ルートで引き続き 200（混在運用）", function()
      local r = client:get("/request", {
        headers = { host = "obo-v1.example",
                    authorization = "Bearer " .. make_token({ sub = "v1-route-v2-user" }) },
      })
      assert.response(r).has.status(200)
    end)

    it("v1.0 トークンを既定ルート（allow_v1_tokens なし）に送ると 401", function()
      local token = jwt.make({ ver = "1.0", iss = MOCK_V1_ISSUER, aud = "test-client-id" })
      local r = client:get("/request", {
        headers = { host = "obo.example", authorization = "Bearer " .. token },
      })
      assert.response(r).has.status(401)
    end)

  end)
end end
