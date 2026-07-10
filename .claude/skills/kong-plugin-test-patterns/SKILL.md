---
name: kong-plugin-test-patterns
description: Kong プラグインの busted テストの書き方パターン集。スキーマテスト・単体テスト（kong.* や resty.http のモック）・統合テスト（モック IdP フィクスチャ）を書くときに必ず参照する。
---

# Kong プラグインのテストパターン

このプラグインのテストは 3 種類。ファイル名の番号で実行順を制御する
（若い番号 = 速いテスト。TDD ではまず単体を書く）。

## 1. スキーマテスト（`spec/obo/01-schema_spec.lua`）

`spec.helpers` の `validate_plugin_config_schema` を使う。Kong の起動は不要。

```lua
local PLUGIN_NAME = "obo"

-- スキーマ検証用のヘルパー関数を用意する
local validate do
  local validate_entity = require("spec.helpers").validate_plugin_config_schema
  local plugin_schema = require("kong.plugins."..PLUGIN_NAME..".schema")
  function validate(data)
    return validate_entity(data, plugin_schema)
  end
end

describe(PLUGIN_NAME .. ": (schema)", function()
  it("有効な最小設定を受け入れる", function()
    local ok, err = validate({
      tenant_id = "11111111-2222-3333-4444-555555555555",
      client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      client_secret = "secret",
      scopes = { "https://graph.microsoft.com/.default" },
      audience = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    })
    assert.is_nil(err)
    assert.is_truthy(ok)
  end)

  it("client_auth_method=private_key_jwt のとき private_key がないと拒否する", function()
    local ok, err = validate({ --[[ ... ]] })
    assert.is_falsy(ok)
    -- err はネストしたテーブル。assert.is_same でエラー構造ごと検証するとメッセージ変化に気づける
  end)
end)
```

ポイント:
- 正常系だけでなく **拒否されるべき設定が確実に拒否されること**をテストする
  （認証プラグインでは誤設定の受け入れが事故につながる）。
- entity_checks（条件付き必須）は成功/失敗の両方向を必ずテストする。

## 2. 単体テスト（`spec/obo/02〜0X-*_spec.lua`）

モジュールを直接 require し、依存（`kong.*`、`resty.http`）をモックする。Kong の起動は不要で数秒で回る。

### kong グローバルのモック

```lua
describe("obo: jwt_validator (unit)", function()
  local jwt_validator

  setup(function()
    -- プラグインコードが参照する kong グローバルを最小限モックする
    _G.kong = {
      log = { debug = function() end, err = function() end, notice = function() end },
      -- kong.cache は callback 実行型: get(key, opts, cb, ...) は cb の結果を返す
      cache = {
        get = function(_, key, opts, cb, ...) return cb(...) end,
        invalidate = function() end,
      },
    }
    jwt_validator = require("kong.plugins.obo.jwt_validator")
  end)

  teardown(function()
    _G.kong = nil
    -- モジュールキャッシュを消して他の spec への影響を防ぐ
    package.loaded["kong.plugins.obo.jwt_validator"] = nil
  end)
end)
```

### resty.http のモック（`package.loaded` を先に差し込む）

対象モジュールを require する**前に** `package.loaded` へ偽物を登録する。

```lua
local mock_response  -- 各テストで差し替える

setup(function()
  package.loaded["resty.http"] = {
    new = function()
      return {
        request_uri = function(_, url, params)
          return mock_response, nil  -- (res, err) の 2 値返し
        end,
      }
    end,
  }
  token_exchange = require("kong.plugins.obo.token_exchange")
end)

teardown(function()
  package.loaded["resty.http"] = nil
  package.loaded["kong.plugins.obo.token_exchange"] = nil
end)

before_each(function()
  -- 例: Entra ID の成功レスポンス（形式は docs/obo/03 参照）
  mock_response = {
    status = 200,
    body = '{"token_type":"Bearer","expires_in":3269,"access_token":"eyJ..."}',
  }
end)
```

### 時刻に依存するテスト

`ngx.time()` は OpenResty 環境で常に存在する。固定したい場合はモジュール側で
時刻取得を関数引数（省略時 `ngx.time`）として注入できる設計にしておくとテストしやすい。

### テスト用鍵とトークン（`spec/fixtures/obo/`）

- テスト専用の RSA 鍵ペア（PEM）と、それで署名した JWT をフィクスチャとして固定コミットする。
- 署名済みテスト JWT の生成スクリプト（resty で実行する Lua）もフィクスチャと一緒に置き、
  再生成の手順をコメントで残す。
- **本物のテナントの鍵・トークン・シークレットは絶対にコミットしない。**

## 3. 統合テスト（`spec/obo/10-integration_spec.lua`）

`spec.helpers` で本物の Kong を起動し、モック IdP を経由した end-to-end を検証する。

```lua
local helpers = require "spec.helpers"
local PLUGIN_NAME = "obo"

for _, strategy in helpers.all_strategies() do if strategy ~= "cassandra" then
  describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })
      local route1 = bp.routes:insert({ hosts = { "test1.example" } })
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = { --[[ token_endpoint をモック IdP に向ける ]] },
      }
      assert(helpers.start_kong({
        database = strategy,
        nginx_conf = "spec/fixtures/custom_nginx.template",
        plugins = "bundled," .. PLUGIN_NAME,
        declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
      }))
    end)

    lazy_teardown(function() helpers.stop_kong(nil, true) end)
    before_each(function() client = helpers.proxy_client() end)
    after_each(function() if client then client:close() end end)

    -- assert.request(r) はモックバックエンドにエコーされたリクエストを検証できる
    it("Authorization ヘッダーが交換後トークンに差し替わる", function()
      local r = client:get("/request", { headers = { host = "test1.example", authorization = "Bearer " .. valid_token } })
      assert.response(r).has.status(200)
      local auth = assert.request(r).has.header("authorization")
      assert.not_equal("Bearer " .. valid_token, auth)
    end)
  end)
end end
```

### モック IdP（Entra ID の代役）

統合テストでは本物の Entra ID に接続できないため、モック IdP をフィクスチャで用意する:

- 方法: `spec/fixtures/custom_nginx.template` をベースに、モック用の `server` ブロックを追加した
  自前テンプレート（例: `spec/fixtures/obo/nginx.template`）を作り、`nginx_conf` で指定する。
- モックが提供するエンドポイント:
  - `/{tenant}/v2.0/.well-known/openid-configuration` → jwks_uri 等を返す JSON
  - `/{tenant}/discovery/v2.0/keys` → テスト用公開鍵の JWKS
  - `/{tenant}/oauth2/v2.0/token` → リクエストパラメータを検証し、成功 JSON またはエラー JSON を返す
- レスポンスの形式は必ず `docs/obo/02` `03` `05` に合わせる（勝手な形式のモックを作ると
  「モックにだけ通るプラグイン」ができてしまう）。
- プラグイン側は、テスト時にトークンエンドポイント URL を差し替えられる設定
  （内部用 config フィールド等）を持つ必要がある。

### 統合テストで必ずカバーするシナリオ

1. 正常系: 有効なトークン → Authorization が交換後トークンに差し替わり 200
2. Authorization ヘッダーなし → 401 + `WWW-Authenticate`
3. 署名が不正なトークン → 401
4. `aud` が不一致のトークン → 401（Entra に送らずプラグインが拒否すること）
5. モック IdP がエラー JSON（400）を返す → 401
6. モック IdP がダウン（接続不可）→ 502
7. 2 回目のリクエストがキャッシュから返る（モック IdP への呼び出し回数で検証）
