-- 受信アクセストークン検証のテスト
-- 仕様: docs/obo/05-token-validation.md
-- resty.http をモックして、OpenID 設定と JWKS の取得を偽装する

local cjson = require "cjson.safe"

-- モック IdP の定数。tenant_id はスキーマの制約（GUID またはドメイン名）に合わせる
local MOCK_BASE   = "https://mock-idp.example"
local TENANT      = "11111111-1111-1111-1111-111111111111"
-- メタデータが自己申告する issuer（Entra の正規形 = {base}/{GUID}/v2.0）
local MOCK_ISSUER = MOCK_BASE .. "/" .. TENANT .. "/v2.0"
local CONFIG_URL  = MOCK_BASE .. "/" .. TENANT .. "/v2.0/.well-known/openid-configuration"
local JWKS_URL    = MOCK_BASE .. "/" .. TENANT .. "/discovery/v2.0/keys"

-- v1.0 形式の issuer（末尾スラッシュ付き）。実 Entra では https://sts.windows.net/{tid}/ だが、
-- プラグインの検証は「ホスト固定」ではなく「テナント GUID の一致」なのでモックホストで表す
local MOCK_V1_ISSUER = MOCK_BASE .. "/" .. TENANT .. "/"

-- v1.0 の OpenID configuration とその JWKS の URL（/v2.0 を含まないパス。docs/obo/05）
local V1_CONFIG_URL = MOCK_BASE .. "/" .. TENANT .. "/.well-known/openid-configuration"
local V1_JWKS_URL   = MOCK_BASE .. "/" .. TENANT .. "/discovery/keys"

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
            -- 呼び出しごとに異なる応答を返したいテスト（例: JWKS のロールオーバー）は
            -- テーブルの代わりに関数を登録できる。関数なら都度呼んで応答を得る
            if type(res) == "function" then
              res = res()
            end
            if not res then
              return nil, "connection refused"
            end
            return res, nil
          end,
        }
      end,
    }

    -- kong.cache のモック: 素通し（毎回コールバックを実行）
    -- renew は Kong 3.9+ の実 API（kong/cache/init.lua）。成功時のみ値を置換するが、
    -- 素通しモックでは get と同様にコールバック結果をそのまま返せば十分
    _G.kong = {
      log = { debug = function() end, err = function() end, warn = function() end },
      cache = {
        get = function(_, _, _, cb, ...) return cb(...) end,
        renew = function(_, _, _, cb, ...) return cb(...) end,
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

  -- 既定でモックのメタデータ issuer と一致する iss を持つトークンを作るローカル関数。
  -- 受信トークンの iss は常に「メタデータの issuer」と照合されるため、
  -- 正常系トークンの iss は MOCK_ISSUER でなければならない
  local function make(claims_override, header_override)
    claims_override = claims_override or {}
    if claims_override.iss == nil then
      claims_override.iss = MOCK_ISSUER
    end
    return jwt.make(claims_override, header_override)
  end

  -- v1.0 形式（ver = "1.0"、iss 末尾スラッシュ付き）のテストトークンを作るローカル関数
  -- header_override は make() と同じく、kid 差し替え等の異常系・鍵ロールオーバーのテスト用
  local function make_v1(claims_override, header_override)
    claims_override = claims_override or {}
    if claims_override.ver == nil then
      claims_override.ver = "1.0"
    end
    if claims_override.iss == nil then
      claims_override.iss = MOCK_V1_ISSUER
    end
    return jwt.make(claims_override, header_override)
  end

  before_each(function()
    http_call_count = 0
    conf = {
      identity_base_url = MOCK_BASE,
      tenant_id = TENANT,
      audiences = { "test-client-id" },
      http_timeout = 1000,
      ssl_verify = false,
      -- issuer（ピン）は未設定。メタデータの issuer が唯一の期待値になる
    }
    -- 正常な OpenID 設定と JWKS を返すモック（形式は docs/obo/05 のメタデータ例に準拠）。
    -- issuer は取得元 authority（{identity_base_url}/{tenant_id}/v2.0）と一致させる（OIDC Discovery）
    http_responses = {
      [CONFIG_URL] = {
        status = 200,
        body = cjson.encode({
          issuer = MOCK_ISSUER,
          jwks_uri = JWKS_URL,
        }),
      },
      [JWKS_URL] = {
        status = 200,
        body = cjson.encode({ keys = { keys.jwk() } }),
      },
    }
  end)

  it("有効なトークンを受け入れてクレームを返す", function()
    local claims, err = jwt_validator.validate(conf, make())
    assert.is_nil(err)
    assert.equal("test-user", claims.sub)
  end)

  -- メタデータの issuer が受信トークンの iss の唯一の期待値であること。
  -- conf.issuer はもはや「iss の期待値の上書き」ではなく「メタデータ issuer のピン」
  it("conf.issuer がメタデータの issuer と一致する場合は受理する（ピン一致）", function()
    conf.issuer = MOCK_ISSUER
    local claims, err = jwt_validator.validate(conf, make())
    assert.is_nil(err)
    assert.is_truthy(claims)
  end)

  it("conf.issuer がメタデータの issuer と一致しない場合は upstream エラーとして拒否する（ピン不一致）", function()
    -- 別の issuer を期待値として設定しても、それが受信トークンの検証に使われてはならない。
    -- メタデータとの不一致は設定または IdP の異常として fail-close する
    conf.issuer = "https://login.microsoftonline.com/" .. TENANT .. "/v2.0"
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- メタデータのキャッシュキーは identity_base_url + tenant_id で構成され conf.issuer を
  -- 含まないため、同じテナントを指す複数のプラグイン設定（別ルート等）でキャッシュが
  -- 共有される。ピンの照合がロード時（キャッシュミス時）だけだと、ピンなしの設定が先に
  -- キャッシュを温めた場合に、不一致ピンを持つ設定がキャッシュヒット経由で素通りしてしまう。
  -- ここではステートフルなキャッシュモックで「設定間キャッシュ共有」を再現し、
  -- キャッシュヒット経路でもピンが毎回照合されることを検証する
  describe("issuer ピンと設定間キャッシュ共有", function()
    local original_cache

    before_each(function()
      -- ステートフルな kong.cache モック: 一度ロードした値をキーごとに保持する
      original_cache = _G.kong.cache
      local store = {}
      _G.kong.cache = {
        get = function(_, cache_key, _, cb, ...)
          if store[cache_key] == nil then
            local value, cb_err = cb(...)
            if value == nil then
              return nil, cb_err
            end
            store[cache_key] = value
          end
          return store[cache_key]
        end,
        invalidate = function(_, cache_key)
          store[cache_key] = nil
        end,
      }
    end)

    after_each(function()
      -- 他のテストに影響しないよう素通しモックへ戻す
      _G.kong.cache = original_cache
    end)

    it("先に温められた共有キャッシュにヒットしても、不一致ピンの設定は拒否される", function()
      -- (a) ピンなしの設定で検証を 1 回通し、共有キャッシュを温める
      local claims, err = jwt_validator.validate(conf, make())
      assert.is_nil(err)
      assert.is_truthy(claims)
      local calls_after_warmup = http_call_count

      -- (b) 同一 identity_base_url / tenant_id で不一致ピンを持つ別の設定
      local pinned = {}
      for k, v in pairs(conf) do pinned[k] = v end
      pinned.issuer = "https://login.microsoftonline.com/" .. TENANT .. "/v2.0"

      local claims2, err2, is_upstream_error = jwt_validator.validate(pinned, make())
      assert.is_nil(claims2)
      assert.is_string(err2)
      assert.is_truthy(is_upstream_error)
      -- キャッシュヒット経路を通っている証拠: メタデータ/JWKS の HTTP 取得回数が増えていない
      assert.equal(calls_after_warmup, http_call_count)
    end)

    it("一致ピンの設定は共有キャッシュにヒットしても受理される", function()
      -- (a) ピンなしの設定でキャッシュを温める
      assert.is_truthy(jwt_validator.validate(conf, make()))
      local calls_after_warmup = http_call_count

      -- (b) メタデータの issuer と一致するピンを持つ別の設定はそのまま通る
      local pinned = {}
      for k, v in pairs(conf) do pinned[k] = v end
      pinned.issuer = MOCK_ISSUER

      local claims, err = jwt_validator.validate(pinned, make())
      assert.is_nil(err)
      assert.is_truthy(claims)
      assert.equal(calls_after_warmup, http_call_count)  -- こちらもキャッシュヒット経路
    end)
  end)

  -- 受け入れ条件: 末尾スラッシュ付き identity_base_url でも issuer 導出・メタデータ URL が
  -- 正しくなる（util.build_tenant_url による正規化の end-to-end 確認）。
  it("末尾スラッシュ付き identity_base_url でも issuer 検証・メタデータ URL が正しい", function()
    conf.identity_base_url = MOCK_BASE .. "/"  -- 末尾スラッシュ付き
    -- 正規化後の URL・issuer は末尾スラッシュなしと同一なので http_responses はそのまま通る
    local claims, err = jwt_validator.validate(conf, make())
    assert.is_nil(err)
    assert.is_truthy(claims)
  end)

  -- 大文字 GUID の tenant_id を設定しても恒常 502 にならないこと。
  -- Entra の実メタデータは（大文字 GUID で要求しても）issuer 内の GUID を小文字で返すため、
  -- 導出値を大文字のまま比較すると metadata issuer 検証が常に失敗する。
  -- util.build_tenant_url の小文字正規化でこれを吸収する。
  it("大文字の tenant_id でもメタデータ issuer 検証が小文字の正規形で通る", function()
    conf.tenant_id = TENANT:upper()  -- モックの URL・issuer は小文字（Entra の正規形を模倣）
    local claims, err = jwt_validator.validate(conf, make())
    assert.is_nil(err)
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
    local token = make()
    -- ペイロード部分の末尾 1 文字を書き換えて署名を無効化する
    local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    local tampered = h .. "." .. p:sub(1, -2) .. (p:sub(-1) == "A" and "B" or "A") .. "." .. s
    local claims = jwt_validator.validate(conf, tampered)
    assert.is_nil(claims)
  end)

  it("alg が RS256 以外なら拒否する（alg confusion 対策）", function()
    local token = make(nil, { alg = "none" })
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
    -- HS256 も拒否（公開鍵を HMAC 鍵として使わせる攻撃の防止）
    token = make(nil, { alg = "HS256" })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("aud が一致しないトークンを拒否する（docs/obo/02: 他アプリ宛てトークンは拒否すべき）", function()
    local token = make({ aud = "https://graph.microsoft.com" })
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
  end)

  it("audiences のいずれかに一致する aud を受理する", function()
    -- v1.0（api://{client_id}）と v2.0（素の client_id）の混在を想定した複数許容
    conf.audiences = { "api://test-client-id", "test-client-id" }
    local claims, err = jwt_validator.validate(conf, make())  -- 既定の aud = "test-client-id"
    assert.is_nil(err)
    assert.is_truthy(claims)
  end)

  it("audiences のどれにも一致しない aud を拒否する", function()
    conf.audiences = { "api://test-client-id", "other-api" }
    assert.is_nil(jwt_validator.validate(conf, make()))
  end)

  it("iss がメタデータの issuer と一致しないトークンを拒否する", function()
    local token = make({ iss = "https://evil.example/" .. TENANT .. "/v2.0" })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("allow_v1_tokens 未設定では v1.0 トークンを拒否し、診断ヒントを返す", function()
    -- ver = "1.0" のトークンは既定では受け付けない。エラー理由（debug ログ専用）に
    -- 恒久対処（requestedAccessTokenVersion=2）へのヒントを含めることで、
    -- 「issuer mismatch」だけでは原因に気づけない問題（設計書 §10 の教訓）を解消する
    local token = make({ ver = "1.0", iss = MOCK_V1_ISSUER })
    local claims, err = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
    assert.is_truthy(err:find("requestedAccessTokenVersion", 1, true))
  end)

  it("ver クレームが欠落したトークンを拒否する", function()
    -- Entra のアクセストークンは必ず ver を含む。欠落は Entra 由来でないか異常なトークン
    local token = make({ ver = false })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("未知の ver（1.0 / 2.0 以外）のトークンを拒否する", function()
    local token = make({ ver = "3.0" })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("期限切れ（exp が過去）のトークンを拒否する", function()
    local token = make({ exp = ngx.time() - 3600 })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("nbf が未来のトークンを拒否する", function()
    local token = make({ nbf = ngx.time() + 3600 })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("exp がない・数値でないトークンを拒否する（RFC 7523: exp は MUST）", function()
    assert.is_nil(jwt_validator.validate(conf, make({ exp = "not-a-number" })))
  end)

  -- 上のテストは「exp が数値でない」ケースのみを検証している。
  -- ここでは claims_override の false 削除機能（fixture 拡張）を使い、
  -- 「exp クレームそのものが存在しない」ケースを別途検証する。
  -- iss 検証（メタデータ issuer との照合）で先に拒否されないよう、
  -- describe 冒頭の make ヘルパー（iss = MOCK_ISSUER を既定にする）を使う
  it("exp クレームが欠落したトークンを拒否する（RFC 7523: exp は MUST）", function()
    local token = make({ exp = false })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  it("nbf が数値でない場合は拒否する", function()
    local token = make({ nbf = "not-a-number" })
    assert.is_nil(jwt_validator.validate(conf, token))
  end)

  -- クロックスキュー境界（±60 秒）の固定テスト。
  -- 実装は `now > claims.exp + CLOCK_SKEW` で拒否するため、ちょうど 60 秒前の exp は
  -- 許容誤差の範囲内（受理）、61 秒前は範囲外（拒否）になるはず。
  -- トークン生成（make）と検証（validate）でそれぞれ ngx.time() を呼ぶため、
  -- 実時刻のままだと秒境界をまたいだ瞬間に ±1 秒ずれてフレークし得る。
  -- そこで ngx.time を固定値を返すスタブに差し替え、生成と検証が同一時刻を使うようにする
  describe("クロックスキュー境界（ngx.time を固定）", function()
    -- 固定する現在時刻。値自体に意味はなく「生成と検証で同一」であることが重要
    local FROZEN_NOW = 1700000000
    local original_ngx_time

    before_each(function()
      original_ngx_time = ngx.time
      ngx.time = function() return FROZEN_NOW end  -- luacheck: ignore
    end)

    after_each(function()
      ngx.time = original_ngx_time  -- luacheck: ignore
    end)

    it("exp がちょうど 60 秒前ならクロックスキュー許容範囲内として受理する", function()
      local token = make({ exp = FROZEN_NOW - 60 })
      assert.is_truthy(jwt_validator.validate(conf, token))
    end)

    it("exp が 61 秒前ならクロックスキュー許容範囲外として拒否する", function()
      local token = make({ exp = FROZEN_NOW - 61 })
      assert.is_nil(jwt_validator.validate(conf, token))
    end)

    -- nbf 側も同様に `now < claims.nbf - CLOCK_SKEW` で拒否するため、
    -- ちょうど 60 秒後の nbf は受理、61 秒後は拒否になるはず
    it("nbf がちょうど 60 秒後ならクロックスキュー許容範囲内として受理する", function()
      local token = make({ nbf = FROZEN_NOW + 60 })
      assert.is_truthy(jwt_validator.validate(conf, token))
    end)

    it("nbf が 61 秒後ならクロックスキュー許容範囲外として拒否する", function()
      local token = make({ nbf = FROZEN_NOW + 61 })
      assert.is_nil(jwt_validator.validate(conf, token))
    end)
  end)

  it("kid がヘッダーにないトークンを拒否する", function()
    local token = make(nil, { kid = false })  -- jwt.make は false でヘッダーからキーを削除する
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
  end)

  it("JWKS に存在しない kid のトークンを拒否する（再取得を 1 回試みた上で）", function()
    local token = make(nil, { kid = "unknown-key" })
    local claims = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
  end)

  it("IdP に接続できない場合はエラーを返す", function()
    http_responses = {}  -- 全 URL で connection refused
    local claims, err = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
  end)

  it("openid-configuration に jwks_uri がない場合はエラーを返す", function()
    http_responses[CONFIG_URL].body = cjson.encode({ issuer = MOCK_ISSUER })
    assert.is_nil(jwt_validator.validate(conf, make()))
  end)

  -- http_get_json の non-200 分岐（接続自体はできるが応答が異常）。
  -- 「接続できない」（res が nil）のケースとは別の分岐なので、明示的に status を非 200 にして確認する
  it("openid-configuration が non-200 を返す場合は upstream エラーを返す（接続不可とは別分岐）", function()
    http_responses[CONFIG_URL] = {
      status = 500,
      body = "Internal Server Error",
    }
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    -- non-200 応答は受信トークンの不正ではなく IdP 側の異常なので、
    -- handler が 502 として扱えるよう upstream エラー（第 3 戻り値 true）になること
    assert.is_true(is_upstream_error)
  end)

  it("JWKS エンドポイントが non-200 を返す場合は upstream エラーを返す（接続不可とは別分岐）", function()
    http_responses[JWKS_URL] = {
      status = 503,
      body = "Service Unavailable",
    }
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    -- 同上: JWKS の non-200 も upstream エラー（502 経路）として扱われること
    assert.is_true(is_upstream_error)
  end)

  -- 設計書（docs/superpowers/specs/2026-07-10-obo-plugin-design.md §5）のエラーマッピングでは
  -- 「受信 JWT の検証失敗（署名・iss・aud・exp）→ 401」と「Entra ID への接続失敗 / 5xx → 502」を
  -- 区別している。JWKS の取得は Entra ID への接続そのものなので、取得に失敗した場合は
  -- 「トークンが不正」（401 相当）ではなく「IdP に接続できない」（502 相当）として
  -- 呼び出し元（handler）が区別できる必要がある。この区別のための第 3 戻り値を検証する。
  it("IdP に接続できない場合は upstream（IdP 到達不能）エラーとして返す（3 番目の戻り値）", function()
    http_responses = {}  -- 全 URL で connection refused
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  it("openid-configuration が不正な形（jwks_uri 欠落）でも upstream エラーとして返す", function()
    http_responses[CONFIG_URL].body = cjson.encode({ issuer = MOCK_ISSUER })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- OIDC Discovery（openid-connect-discovery-1_0）: メタデータの issuer は取得元 authority と
  -- 完全一致しなければならない。一致しない場合は IdP 側メタデータの異常なので upstream エラー扱い。
  it("メタデータの issuer が期待値と一致しない場合は upstream エラーとして拒否する", function()
    http_responses[CONFIG_URL].body = cjson.encode({
      issuer = "https://evil.example/" .. TENANT .. "/v2.0",
      jwks_uri = JWKS_URL,
    })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- jwks_uri のホストが identity_base_url と異なると、署名鍵を攻撃者ホストから取得させられる。
  -- OIDC メタデータの整合性違反として upstream エラー扱いで拒否する。
  it("jwks_uri のホストが identity_base_url と異なる場合は upstream エラーとして拒否する", function()
    local evil_jwks = "https://evil.example/" .. TENANT .. "/discovery/v2.0/keys"
    http_responses[CONFIG_URL].body = cjson.encode({
      issuer = MOCK_ISSUER,
      jwks_uri = evil_jwks,
    })
    -- 攻撃者ホストが正規の鍵で応答できても（署名検証自体は通る）ホスト不一致で拒否すること
    http_responses[evil_jwks] = {
      status = 200,
      body = cjson.encode({ keys = { keys.jwk() } }),
    }
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- identity_base_url が https のときは jwks_uri も https を要求する（平文での鍵取得を防ぐ）。
  it("jwks_uri が https でない場合は upstream エラーとして拒否する（identity_base_url が https）", function()
    local plain_jwks = "http://mock-idp.example/" .. TENANT .. "/discovery/v2.0/keys"
    http_responses[CONFIG_URL].body = cjson.encode({
      issuer = MOCK_ISSUER,
      jwks_uri = plain_jwks,
    })
    -- 平文 http でも鍵取得自体は成功しうるが、scheme 検証で拒否すること
    http_responses[plain_jwks] = {
      status = 200,
      body = cjson.encode({ keys = { keys.jwk() } }),
    }
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- 署名鍵の issuer 検証（docs/obo/05 "Validate the signing key issuer"）。
  -- Entra の JWKS は鍵エントリに issuer フィールドを含むことがある（実 JWKS で確認済み。
  -- 多くは "{tenantid}" プレースホルダ入り、一部は具体的な GUID）。存在する場合は
  -- プレースホルダを実テナントに置換した上でメタデータの issuer と一致しない鍵を使わない。
  it("JWKS の鍵に issuer があり不一致なら、その鍵を署名検証に使わない（結果として鍵 0 件で upstream エラー）", function()
    local jwk = keys.jwk()
    jwk.issuer = "https://evil.example/{tenantid}/v2.0"
    http_responses[JWKS_URL].body = cjson.encode({ keys = { jwk } })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    -- この JWKS はこの 1 件しか鍵を持たず、その唯一の鍵が issuer 不一致で除外されるため、
    -- 利用可能な鍵が結果的に 0 件になる。「鍵 issuer フィルターで全滅した設定不整合」
    -- そのものであり、JWKS 鍵 0 件の fail-close ルールにより upstream エラー（502 経路）になる
    assert.is_truthy(is_upstream_error)
  end)

  it("JWKS の鍵の issuer の {tenantid} プレースホルダを実テナントに置換して一致すれば受理する", function()
    local jwk = keys.jwk()
    jwk.issuer = MOCK_BASE .. "/{tenantid}/v2.0"
    http_responses[JWKS_URL].body = cjson.encode({ keys = { jwk } })
    local claims, err = jwt_validator.validate(conf, make())
    assert.is_nil(err)
    assert.is_truthy(claims)
  end)

  it("JWKS の鍵の issuer が具体値でメタデータ issuer と一致すれば受理する", function()
    local jwk = keys.jwk()
    jwk.issuer = MOCK_ISSUER
    http_responses[JWKS_URL].body = cjson.encode({ keys = { jwk } })
    local claims, err = jwt_validator.validate(conf, make())
    assert.is_nil(err)
    assert.is_truthy(claims)
  end)

  -- 外部レビュー指摘: JWKS の利用可能な鍵が 0 件のまま正常キャッシュしてしまうと、
  -- 実 Entra ではあり得ないはずの「鍵 0 件」状態が METADATA_TTL の間キャッシュされ続け、
  -- その間の全トークンが本来の 502（上流異常）ではなく 401（トークン不正）になってしまう。
  -- ロード全体を失敗させ upstream エラーとして fail-close することを確認する。
  -- last_refetch（未知 kid 再取得のデバウンス用モジュール state）が他テストの影響を
  -- 受けないよう、この describe 内でモジュールを再 require してクリーンな状態から始める
  describe("JWKS 鍵 0 件の fail-close", function()
    before_each(function()
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    after_each(function()
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    it("v2.0 JWKS の利用可能な鍵が 0 件なら upstream エラー", function()
      http_responses[JWKS_URL].body = cjson.encode({ keys = {} })
      local claims, err, is_upstream = jwt_validator.validate(conf, make())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream)
    end)
  end)

  -- ドメイン形式の tenant_id（contoso.onmicrosoft.com 等）のサポート。
  -- Entra の実メタデータはドメイン名で要求しても issuer を正規化済みの GUID 形式
  -- （{base}/{GUID}/v2.0）で返す（実メタデータで裏取り済み）。そのため導出値との完全一致は
  -- 成立せず、「同一ホスト + /{GUID}/v2.0 形式」であることを検証し、その issuer を
  -- 受信トークンの iss の期待値として使う。
  describe("ドメイン形式の tenant_id", function()
    local DOMAIN        = "contoso.onmicrosoft.com"
    local DOMAIN_CONFIG = MOCK_BASE .. "/" .. DOMAIN .. "/v2.0/.well-known/openid-configuration"
    local DOMAIN_JWKS   = MOCK_BASE .. "/" .. DOMAIN .. "/discovery/v2.0/keys"

    before_each(function()
      conf.tenant_id = DOMAIN
      -- メタデータはドメインのパスで取得されるが、issuer は GUID 形式（MOCK_ISSUER）を返す
      http_responses[DOMAIN_CONFIG] = {
        status = 200,
        body = cjson.encode({
          issuer = MOCK_ISSUER,
          jwks_uri = DOMAIN_JWKS,
        }),
      }
      http_responses[DOMAIN_JWKS] = {
        status = 200,
        body = cjson.encode({ keys = { keys.jwk() } }),
      }
    end)

    it("メタデータの GUID issuer と一致する iss のトークンを受理する", function()
      local claims, err = jwt_validator.validate(conf, make())  -- make() の iss = MOCK_ISSUER
      assert.is_nil(err)
      assert.is_truthy(claims)
    end)

    it("メタデータの issuer が GUID 形式でない場合は upstream エラーとして拒否する", function()
      -- ドメインのままの issuer は Entra の正規形ではない（テナントの同定が成立しない）
      http_responses[DOMAIN_CONFIG].body = cjson.encode({
        issuer = MOCK_BASE .. "/" .. DOMAIN .. "/v2.0",
        jwks_uri = DOMAIN_JWKS,
      })
      local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream_error)
    end)

    it("メタデータの issuer が別ホストの場合は upstream エラーとして拒否する", function()
      http_responses[DOMAIN_CONFIG].body = cjson.encode({
        issuer = "https://evil.example/" .. TENANT .. "/v2.0",
        jwks_uri = DOMAIN_JWKS,
      })
      local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream_error)
    end)

    it("メタデータの GUID issuer と一致しない iss のトークンを拒否する（401）", function()
      -- 同一ホストの別テナント GUID を名乗るトークンは拒否されること
      local other = "22222222-2222-2222-2222-222222222222"
      local token = make({ iss = MOCK_BASE .. "/" .. other .. "/v2.0" })
      local claims, _, is_upstream_error = jwt_validator.validate(conf, token)
      assert.is_nil(claims)
      assert.is_falsy(is_upstream_error)
    end)
  end)

  it("JWKS に存在しない kid（IdP 自体は正常応答）は upstream エラーにしない（401 のまま）", function()
    local token = make(nil, { kid = "unknown-key" })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_falsy(is_upstream_error)
  end)

  it("署名が不正なトークンは upstream エラーにしない（401 のまま）", function()
    local token = make()
    local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    local tampered = h .. "." .. p:sub(1, -2) .. (p:sub(-1) == "A" and "B" or "A") .. "." .. s
    local claims, _, is_upstream_error = jwt_validator.validate(conf, tampered)
    assert.is_nil(claims)
    assert.is_falsy(is_upstream_error)
  end)

  -- kid は一致するが、JWKS 上の当該エントリ自体が壊れている（n/e が不正等）ケース。
  -- これは受信トークンの不正ではなく Entra ID 側データの異常なので、他の JWKS 取得失敗と
  -- 同様に upstream エラー（3 番目の戻り値 true → 502）として扱うべき
  it("kid が一致する JWK が壊れている場合は upstream エラーとして返す（3 番目の戻り値）", function()
    http_responses[JWKS_URL].body =
      cjson.encode({ keys = { { kty = "RSA", kid = keys.kid, n = "!!!", e = "!!!" } } })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- Fix 1: 未知 kid による JWKS 再取得のデバウンス。
  -- kong.cache のモックは素通し（毎回コールバック実行）のため、実キャッシュの有無に関わらず
  -- 未知 kid 時の「renew（kong.cache:renew）経由の再取得」のもう一往復が抑止されることを
  -- HTTP 呼び出し回数の差分で検証する。
  -- last_refetch はモジュール state なので、他テストの影響を受けないよう describe 内で
  -- 都度モジュールを再 require してリセットする
  describe("未知 kid の再取得デバウンス", function()
    before_each(function()
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    it("同一ワーカー内で連続する未知 kid は 2 回目の再取得を抑止する", function()
      local token = make(nil, { kid = "unknown-key" })

      local claims1, err1 = jwt_validator.validate(conf, token)
      assert.is_nil(claims1)
      assert.is_string(err1)
      local calls_after_first = http_call_count

      local claims2, err2 = jwt_validator.validate(conf, token)
      assert.is_nil(claims2)
      assert.is_string(err2)
      local calls_after_second = http_call_count

      -- kong.cache モックは素通し（毎回コールバック実行）なので、1 回の validate で
      -- 「kong.cache:get 経由の通常取得」と「未知 kid 検出後の kong.cache:renew 経由の再取得」の
      -- 2 往復（openid-config + jwks 各 2 回）= 4 回になる。
      -- デバウンスされていれば 2 回目の validate は「通常取得」の 2 回だけで、
      -- renew（再取得）の 2 回は発生しない。
      assert.equal(4, calls_after_first)
      assert.equal(2, calls_after_second - calls_after_first)
    end)
  end)

  -- Issue #3: 未知 kid の再取得を「取得成功後に置換」方式へ変更する。
  -- 先に invalidate してから取り直すと、再取得が失敗したとき（IdP 一時断など）に
  -- 本来まだ有効だった正常な JWKS まで失う。そこで「新しい JWKS の取得に成功した場合のみ
  -- 既存キャッシュを置換する」ことを、値を実際に保持するステートフルな kong.cache モックで検証する。
  describe("未知 kid の再取得（取得成功後に置換）", function()
    local cache_store, invalidate_count, orig_cache

    before_each(function()
      -- last_refetch（モジュール state）をリセットするため再 require する
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")

      -- 素通しモックではなく、実際に値を保持し invalidate を尊重するモックへ差し替える。
      -- これにより「取得失敗時にキャッシュが温存される」ことをキャッシュ状態そのもので検証できる
      cache_store = {}
      invalidate_count = 0
      orig_cache = _G.kong.cache
      _G.kong.cache = {
        get = function(_, key, _, cb, ...)
          -- キャッシュヒットなら保持値を返す（コールバックは呼ばない）
          if cache_store[key] ~= nil then
            return cache_store[key]
          end
          local v, err = cb(...)
          if v == nil then
            return nil, err
          end
          cache_store[key] = v
          return v
        end,
        -- renew: Kong 3.9+ の実 API（kong/cache/init.lua → mlcache:renew）と同じ契約を模す。
        -- コールバックを必ず実行し、成功時のみ既存値を置換する。失敗時は既存値に触れず
        -- nil, err を返す（実 mlcache はロック下で shm へ書かずに返す）
        renew = function(_, key, _, cb, ...)
          local v, err = cb(...)
          if v == nil then
            return nil, err
          end
          cache_store[key] = v
          return v
        end,
        invalidate = function(_, key)
          invalidate_count = invalidate_count + 1
          cache_store[key] = nil
        end,
      }
    end)

    after_each(function()
      -- 他テストに影響しないよう素通しモックへ戻す
      _G.kong.cache = orig_cache
      -- この describe 内のテストで進んだ last_refetch（モジュール state）を持ち越さないよう、
      -- モジュールも再 require して初期状態へ復元する（後続テスト追加時の前提を保つ衛生策）
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    it("再取得で新しい鍵を取得できればロールオーバー後のトークンを検証成功する", function()
      -- ロールオーバーを模す: JWKS エンドポイントは 1 回目に旧鍵のみ、
      -- 2 回目（再取得）で新 kid を含む JWKS を返す。
      -- 新鍵はテスト鍵の公開鍵を流用し kid だけ変える（署名はテスト秘密鍵で有効なまま）
      local new_kid = "test-key-2"
      local rotated_jwk = keys.jwk()
      rotated_jwk.kid = new_kid

      local jwks_seq = 0
      http_responses[JWKS_URL] = function()
        jwks_seq = jwks_seq + 1
        if jwks_seq == 1 then
          return { status = 200, body = cjson.encode({ keys = { keys.jwk() } }) }
        end
        return { status = 200, body = cjson.encode({ keys = { keys.jwk(), rotated_jwk } }) }
      end

      local token = make(nil, { kid = new_kid })
      local claims, err = jwt_validator.validate(conf, token)

      assert.is_nil(err)
      assert.is_truthy(claims)
      assert.equal("test-user", claims.sub)
      -- 置換は renew（成功時のみ上書き）で行われ、クラスタ全体へ無効化イベントを配信する
      -- invalidate は一切呼ばれない（他ノードの正常キャッシュを消さないため）
      assert.equal(0, invalidate_count)

      -- 置換後は新 kid がキャッシュ済みなので、以後の同 kid は再取得せずに検証できる
      local calls_before = http_call_count
      local claims2 = jwt_validator.validate(conf, make(nil, { kid = new_kid }))
      assert.is_truthy(claims2)
      assert.equal(0, http_call_count - calls_before)
    end)

    it("再取得が失敗しても既存の JWKS キャッシュを失わない（stale 温存）", function()
      -- まず正常なトークンで JWKS（旧鍵 test-key-1）をキャッシュに載せる
      local ok_claims = jwt_validator.validate(conf, make())
      assert.is_truthy(ok_claims)
      assert.equal(0, invalidate_count)

      -- IdP を全断させる（openid-config も jwks も接続不可）
      http_responses = {}

      -- 未知 kid のトークンは再取得を試みるが、IdP 断で失敗する
      local claims, err, is_upstream =
        jwt_validator.validate(conf, make(nil, { kid = "test-key-2" }))
      assert.is_nil(claims)
      assert.is_string(err)
      -- IdP 到達不能は upstream エラー（502 相当）として返す
      assert.is_truthy(is_upstream)
      -- 取得失敗時は invalidate されない = 既存キャッシュが温存される
      assert.equal(0, invalidate_count)

      -- IdP は断のままでも、キャッシュ済みの旧鍵 test-key-1 のトークンは引き続き検証できる
      local claims2, err2 = jwt_validator.validate(conf, make())
      assert.is_nil(err2)
      assert.is_truthy(claims2)
    end)

    it("再投入（renew の書き込み）が失敗しても既存の JWKS キャッシュを失わない", function()
      -- まず正常なトークンで JWKS（旧鍵 test-key-1）をキャッシュに載せる
      assert.is_truthy(jwt_validator.validate(conf, make()))

      -- renew を「取得（コールバック）は成功するが、キャッシュへの書き込みで失敗する」
      -- ケースに差し替える（実 mlcache では shm 書き込み失敗時に既存値へ触れず err を返す）
      _G.kong.cache.renew = function(_, _, _, cb, ...)
        local v, err = cb(...)
        if v == nil then
          return nil, err
        end
        return nil, "failed to renew key in node cache: could not write to lua_shared_dict"
      end

      -- 未知 kid → 再取得は成功するが再投入に失敗する
      local claims, err, is_upstream =
        jwt_validator.validate(conf, make(nil, { kid = "test-key-2" }))
      assert.is_nil(claims)
      assert.is_string(err)
      -- 受信トークンの不正ではなくキャッシュ層の異常なので upstream エラー（502 経路）
      assert.is_truthy(is_upstream)
      -- invalidate は呼ばれず、既存キャッシュが温存される
      assert.equal(0, invalidate_count)

      -- 旧鍵 test-key-1 のトークンは引き続き検証できる（HTTP 再取得も不要 = キャッシュヒット）
      local calls_before = http_call_count
      assert.is_truthy(jwt_validator.validate(conf, make()))
      assert.equal(0, http_call_count - calls_before)
    end)

    -- Medium 2: 再取得が失敗した直後の抑止期間（30 秒デバウンス）中に来た未知 kid は、
    -- 「トークンが不正」（401）ではなく直前と同じ IdP 障害が続いているとみなして
    -- upstream エラー（502 経路）として分類すべき。誤分類だとクライアントに
    -- 「トークンを直せ」という誤ったシグナルを返してしまう
    it("再取得失敗後の抑止期間中の未知 kid は upstream エラー（502 経路）として返す", function()
      -- まず正常なトークンで JWKS（旧鍵 test-key-1）をキャッシュに載せる
      assert.is_truthy(jwt_validator.validate(conf, make()))

      -- IdP を全断させる
      http_responses = {}

      -- 1 回目の未知 kid: 再取得を試みて失敗 → upstream エラー
      local _, err1, up1 = jwt_validator.validate(conf, make(nil, { kid = "test-key-2" }))
      assert.is_string(err1)
      assert.is_truthy(up1)

      -- 2 回目（抑止期間中）: 再取得はデバウンスで抑止されるが、直前の失敗が
      -- 続いているとみなして upstream エラーとして返すこと
      local claims2, err2, up2 = jwt_validator.validate(conf, make(nil, { kid = "test-key-2" }))
      assert.is_nil(claims2)
      assert.is_string(err2)
      assert.is_truthy(up2)

      -- 回帰確認: 抑止期間中でも、キャッシュ済みの旧鍵 test-key-1 のトークンは検証成功する
      assert.is_truthy(jwt_validator.validate(conf, make()))
    end)

    it("再取得成功後の抑止期間中の未知 kid は upstream エラーにしない（401 のまま）", function()
      -- IdP は正常応答のまま。未知 kid → 再取得成功、しかし kid は本当に存在しない
      local _, err1, up1 = jwt_validator.validate(conf, make(nil, { kid = "no-such-kid" }))
      assert.is_string(err1)
      assert.is_falsy(up1)

      -- 抑止期間中の 2 回目も、直前の再取得は成功している（IdP は健在）ので 401 のまま
      local claims2, err2, up2 = jwt_validator.validate(conf, make(nil, { kid = "no-such-kid" }))
      assert.is_nil(claims2)
      assert.is_string(err2)
      assert.is_falsy(up2)
    end)
  end)

  -- Issue #13: JWK→pkey 変換のワーカーローカルメモ化。
  -- JWKS キャッシュは shm 越し共有のため JWK を JSON 文字列で保持しており、
  -- 毎リクエスト pkey.new(JWK) で公開鍵をパースし直していた（実測 ~3.9us/req）。
  -- 同一 JWK JSON に対する pkey オブジェクトをワーカーローカルにメモ化して再パースを避ける。
  -- メモのキーは JWK JSON 文字列そのもの（内容アドレス方式）なので、鍵ロールオーバーで
  -- JWK が変われば別エントリになり、古い pkey が誤って使われることはない。
  describe("JWK→pkey メモ化", function()
    -- pkey.new(JWK) の呼び出し回数を数えるため resty.openssl.pkey をラップする。
    -- 既にロード済みの fixtures（jwt/keys）は自前の local に本物の pkey を捕捉しているので
    -- 影響を受けない。ラップ後に再 require する jwt_validator だけがカウンタ付き pkey を使う。
    local real_pkey, jwk_new_count

    before_each(function()
      real_pkey = package.loaded["resty.openssl.pkey"]
      jwk_new_count = 0
      package.loaded["resty.openssl.pkey"] = setmetatable({
        new = function(inp, opts)
          -- format=JWK のパースだけを数える（PEM 署名などは対象外）
          if type(opts) == "table" and opts.format == "JWK" then
            jwk_new_count = jwk_new_count + 1
          end
          return real_pkey.new(inp, opts)
        end,
      }, { __index = real_pkey })
      -- ワーカーローカルなメモ状態をリセットするため毎回再 require する
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    after_each(function()
      package.loaded["resty.openssl.pkey"] = real_pkey
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    it("同一 JWK は 2 回目以降 pkey.new(JWK) を呼ばずメモから返す", function()
      local token = make()

      local claims1 = jwt_validator.validate(conf, token)
      assert.is_truthy(claims1)
      assert.equal(1, jwk_new_count)

      -- 2 回目: JWK は同一なのでメモヒットし、pkey.new(JWK) は増えない
      local claims2 = jwt_validator.validate(conf, token)
      assert.is_truthy(claims2)
      assert.equal(1, jwk_new_count)
    end)

    it("鍵ロールオーバー時に stale な pkey を使わず新しい鍵で検証する", function()
      local pkey = real_pkey
      local util = require "kong.plugins.obo.util"

      -- 1 回目: 既定の鍵 A で検証しメモに載せる
      local claimsA = jwt_validator.validate(conf, make())
      assert.is_truthy(claimsA)

      -- 鍵 B を新規生成し JWKS を差し替える（kid も変える = ロールオーバー相当）
      local keyB = assert(pkey.new({ type = "RSA", bits = 2048 }))
      local params = keyB:get_parameters()
      local jwkB = {
        kty = "RSA", use = "sig", kid = "rotated-key-2",
        n = util.b64url_encode(params.n:to_binary()),
        e = util.b64url_encode(params.e:to_binary()),
      }
      http_responses[JWKS_URL] = {
        status = 200,
        body = cjson.encode({ keys = { jwkB } }),
      }

      -- 鍵 B で署名したトークンを組み立てる（iss はメタデータの issuer と一致させる）
      local now = ngx.time()
      local header = { alg = "RS256", typ = "JWT", kid = "rotated-key-2" }
      local claims = {
        iss = MOCK_ISSUER,
        aud = "test-client-id", sub = "test-user", exp = now + 3600, nbf = now,
        ver = "2.0",
      }
      local signing_input = util.b64url_encode(cjson.encode(header))
          .. "." .. util.b64url_encode(cjson.encode(claims))
      local sig = assert(keyB:sign(signing_input, "sha256"))
      local tokenB = signing_input .. "." .. util.b64url_encode(sig)

      -- stale な鍵 A の pkey を使い回していたら署名検証に失敗して nil になる
      local claimsB, err = jwt_validator.validate(conf, tokenB)
      assert.is_nil(err)
      assert.is_truthy(claimsB)
      assert.equal("test-user", claimsB.sub)
    end)
  end)

  describe("v1.0 トークン（allow_v1_tokens = true）", function()
    before_each(function()
      conf.allow_v1_tokens = true
      -- v1.0 のメタデータと JWKS のモック。issuer は {scheme}://{host}/{GUID}/（末尾スラッシュ）
      http_responses[V1_CONFIG_URL] = {
        status = 200,
        body = cjson.encode({ issuer = MOCK_V1_ISSUER, jwks_uri = V1_JWKS_URL }),
      }
      http_responses[V1_JWKS_URL] = {
        status = 200,
        body = cjson.encode({ keys = { keys.jwk() } }),
      }
    end)

    it("v1.0 トークンを受理してクレームを返す", function()
      local claims, err = jwt_validator.validate(conf, make_v1())
      assert.is_nil(err)
      assert.equal("test-user", claims.sub)
    end)

    it("v2.0 トークンも引き続き受理する（混在運用）", function()
      local claims, err = jwt_validator.validate(conf, make())
      assert.is_nil(err)
      assert.is_truthy(claims)
    end)

    it("v1.0 トークンでも aud は audiences と照合される", function()
      assert.is_nil(jwt_validator.validate(conf, make_v1({ aud = "someone-else" })))
    end)

    it("v1.0 トークンの iss が v1.0 メタデータの issuer と一致しなければ拒否する", function()
      local token = make_v1({ iss = MOCK_BASE .. "/22222222-2222-2222-2222-222222222222/" })
      assert.is_nil(jwt_validator.validate(conf, token))
    end)

    it("v1.0 メタデータの issuer のテナント GUID が v2.0 と異なる場合は upstream エラー", function()
      -- Entra の署名鍵は全テナント共通のため、テナント GUID の一致が v1 issuer 検証の要
      http_responses[V1_CONFIG_URL].body = cjson.encode({
        issuer = MOCK_BASE .. "/22222222-2222-2222-2222-222222222222/",
        jwks_uri = V1_JWKS_URL,
      })
      local claims, err, is_upstream = jwt_validator.validate(conf, make_v1())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream)
    end)

    it("v1.0 メタデータの issuer が末尾スラッシュなしの形式なら upstream エラー", function()
      http_responses[V1_CONFIG_URL].body = cjson.encode({
        issuer = MOCK_BASE .. "/" .. TENANT,  -- 末尾スラッシュ欠落 = v1.0 の正規形でない
        jwks_uri = V1_JWKS_URL,
      })
      local claims, err, is_upstream = jwt_validator.validate(conf, make_v1())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream)
    end)

    it("v1.0 メタデータの取得に失敗するとロード全体が失敗する（fail-close）", function()
      -- 部分成功（v2 だけ有効）を作らない: v2.0 トークンの検証も upstream エラーになる
      http_responses[V1_CONFIG_URL] = nil
      local claims, err, is_upstream = jwt_validator.validate(conf, make())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream)
    end)

    it("v1.0 JWKS の jwks_uri が別ホストなら upstream エラー", function()
      http_responses[V1_CONFIG_URL].body = cjson.encode({
        issuer = MOCK_V1_ISSUER,
        jwks_uri = "https://evil.example/" .. TENANT .. "/discovery/keys",
      })
      local claims, err, is_upstream = jwt_validator.validate(conf, make_v1())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream)
    end)

    it("鍵ロールオーバー後に新しい kid で届いた v1.0 トークンも issuer_v1 が伝搬して受理される（renew 経路の回帰ガード）", function()
      -- get_signing_key は未知 kid を検出すると kong.cache:renew でメタデータを再取得し、
      -- その結果（issuer_v1 を含む）をそのまま返す（jwt_validator.lua の get_signing_key
      -- 末尾、fresh.keys[kid] が見つかったときの return 文）。この renew 経路で issuer_v1 の
      -- 伝搬が抜け落ちる回帰が起きると、鍵ロールオーバー直後に届いた v1.0 トークンだけが
      -- 「issuer mismatch」で 401 になる（v2.0 トークンや、ロールオーバー後にキャッシュが
      -- 温まった後の v1.0 トークンでは再現しない、renew 経路特有の回帰のため見逃しやすい）。
      --
      -- last_refetch（未知 kid 再取得のデバウンス用）はモジュールローカルな state なので、
      -- 他テストで進んだ状態を持ち越さないよう、ここでモジュールを再 require して
      -- クリーンな状態から始める（674 行目付近の既存ロールオーバーテストと同じ作法）
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")

      -- ロールオーバーを模す: v1.0 JWKS エンドポイントは 1 回目（kong.cache:get 経由の
      -- 通常取得）に旧鍵のみ、2 回目（未知 kid 検出後の kong.cache:renew 経由の再取得）で
      -- 新 kid を含む JWKS を返す。新鍵はテスト鍵の公開鍵を流用し kid だけ変える
      -- （署名はテスト秘密鍵で有効なまま。727 行目付近の v2.0 ロールオーバーテストと同じ手法）
      local new_kid = "test-key-2"
      local rotated_jwk = keys.jwk()
      rotated_jwk.kid = new_kid

      local v1_jwks_seq = 0
      http_responses[V1_JWKS_URL] = function()
        v1_jwks_seq = v1_jwks_seq + 1
        if v1_jwks_seq == 1 then
          return { status = 200, body = cjson.encode({ keys = { keys.jwk() } }) }
        end
        return { status = 200, body = cjson.encode({ keys = { keys.jwk(), rotated_jwk } }) }
      end

      local token = make_v1(nil, { kid = new_kid })
      local claims, err = jwt_validator.validate(conf, token)

      assert.is_nil(err)
      assert.is_truthy(claims)
      assert.equal("test-user", claims.sub)

      -- 後続テストへモジュール state（last_refetch 等）を持ち越さないよう、ここでも
      -- 再 require してクリーンな状態に戻す
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    -- 外部レビュー指摘（High）: v1/v2 の鍵を単一マップにマージしていたため、
    -- 一方の JWKS にしか存在しない kid でも他方のバージョンのトークンを検証できてしまっていた
    -- （Microsoft の検証手順は「ver に対応するメタデータ文書で検証する」こと。docs/obo/05）。
    -- 鍵セットを v1/v2 で分離し、フォールバックしないことを確認する。
    describe("鍵セットの分離（v1/v2 でフォールバックしない）", function()
      before_each(function()
        -- last_refetch（未知 kid 再取得のデバウンス用モジュール state）が他テストの影響を
        -- 受けないよう、都度モジュールを再 require してクリーンな状態から始める
        package.loaded["kong.plugins.obo.jwt_validator"] = nil
        jwt_validator = require("kong.plugins.obo.jwt_validator")

        -- v1.0 JWKS は v2.0 と同じ鍵材料（秘密鍵は共通）だが kid だけ異なるものを返す。
        -- 署名はどちらの kid を名乗っても検証が通ってしまう鍵なので、kid の選択（＝
        -- どちらの JWKS から鍵を引いたか）だけが受理・拒否を決める純粋なテストになる
        local v1_jwk = keys.jwk()
        v1_jwk.kid = "v1-key-1"
        http_responses[V1_JWKS_URL].body = cjson.encode({ keys = { v1_jwk } })
      end)

      after_each(function()
        package.loaded["kong.plugins.obo.jwt_validator"] = nil
        jwt_validator = require("kong.plugins.obo.jwt_validator")
      end)

      it("v1.0 トークンの署名鍵は v1.0 JWKS からのみ選択される（v2 側の kid にフォールバックしない）", function()
        -- v2.0 側にしかない kid "test-key-1" を名乗る v1.0 トークンは拒否される
        local token_wrong_kid = make_v1(nil, { kid = "test-key-1" })
        local claims1, err1, up1 = jwt_validator.validate(conf, token_wrong_kid)
        assert.is_nil(claims1)
        assert.is_string(err1)
        assert.is_falsy(up1)

        -- v1.0 側の kid "v1-key-1" を名乗る v1.0 トークンは受理される
        local token_right_kid = make_v1(nil, { kid = "v1-key-1" })
        local claims2, err2 = jwt_validator.validate(conf, token_right_kid)
        assert.is_nil(err2)
        assert.is_truthy(claims2)
      end)

      it("v2.0 トークンは v1.0 JWKS だけにある kid では検証されない", function()
        local token = make(nil, { kid = "v1-key-1" })
        local claims, err, up = jwt_validator.validate(conf, token)
        assert.is_nil(claims)
        assert.is_string(err)
        assert.is_falsy(up)
      end)
    end)

    it("v1.0 JWKS の利用可能な鍵が 0 件ならロード全体が upstream エラーになる", function()
      -- V1_JWKS が空の鍵セットを返すと、v1.0 トークンだけでなく v2.0 トークンの検証も
      -- upstream エラーになる（load_metadata は v1/v2 を一括でロードするため fail-close する）。
      -- これにより「空の v1.0 JWKS からは v1.0 トークンを絶対に受理できない」ことを保証する
      -- （レビュー指摘の再現手順つぶし: 空の v1 JWKS が v1.0 トークンの受理につながらない）
      http_responses[V1_JWKS_URL].body = cjson.encode({ keys = {} })
      local claims, err, is_upstream = jwt_validator.validate(conf, make())
      assert.is_nil(claims)
      assert.is_string(err)
      assert.is_truthy(is_upstream)
    end)

    it("v1.0 issuer のホストが identity_base_url と異なっていても受理される（実 Entra の sts.windows.net 構成）", function()
      -- 実 Entra は v1.0 issuer のホストが sts.windows.net でメタデータ取得元と異なる。
      -- 誤ってホスト一致を要求する回帰を検出する
      local other_host_issuer = "https://sts.mock-other.example/" .. TENANT .. "/"
      http_responses[V1_CONFIG_URL].body = cjson.encode({
        issuer = other_host_issuer,
        jwks_uri = V1_JWKS_URL,
      })
      local token = make_v1({ iss = other_host_issuer })
      local claims, err = jwt_validator.validate(conf, token)
      assert.is_nil(err)
      assert.is_truthy(claims)
    end)
  end)

  -- キャッシュキーが設定差分（allow_v1_tokens / ssl_verify）で分離されること。
  -- allow_v1_tokens: 共有されると、フラグなし設定が先に温めたエントリ（issuer_v1 なし）を
  -- フラグあり設定が引いてしまい、v1.0 トークンが TTL 満了まで失敗し続ける（設計書 §5.2）。
  -- ssl_verify: 共有されると、ssl_verify=false の設定が TLS 検証なしで取得・キャッシュした
  -- 鍵を ssl_verify=true の設定が再利用してしまい、検証ありの信頼境界へ越境する（外部レビュー指摘）
  describe("設定差分とキャッシュキーの分離", function()
    local original_cache

    before_each(function()
      -- ステートフルな kong.cache モック（issuer ピンの describe と同じパターン）
      original_cache = _G.kong.cache
      local store = {}
      _G.kong.cache = {
        get = function(_, cache_key, _, cb, ...)
          if store[cache_key] == nil then
            local value, cb_err = cb(...)
            if value == nil then
              return nil, cb_err
            end
            store[cache_key] = value
          end
          return store[cache_key]
        end,
        invalidate = function(_, cache_key)
          store[cache_key] = nil
        end,
      }
      -- v1 系のモック応答も登録しておく
      http_responses[V1_CONFIG_URL] = {
        status = 200,
        body = cjson.encode({ issuer = MOCK_V1_ISSUER, jwks_uri = V1_JWKS_URL }),
      }
      http_responses[V1_JWKS_URL] = {
        status = 200,
        body = cjson.encode({ keys = { keys.jwk() } }),
      }
    end)

    after_each(function()
      _G.kong.cache = original_cache
    end)

    it("フラグなし設定が温めたキャッシュを、フラグあり設定は共有しない", function()
      -- (a) allow_v1_tokens なしの設定で温める（v2 のみのエントリができる）
      assert.is_truthy(jwt_validator.validate(conf, make()))
      local calls_after_warmup = http_call_count

      -- (b) フラグありの設定は別キーで自分のエントリをロードする（HTTP 取得が増える）ため、
      --     v1.0 トークンが正しく受理される
      local v1conf = {}
      for k, v in pairs(conf) do v1conf[k] = v end
      v1conf.allow_v1_tokens = true

      local claims, err = jwt_validator.validate(v1conf, make_v1())
      assert.is_nil(err)
      assert.is_truthy(claims)
      assert.is_true(http_call_count > calls_after_warmup)
    end)

    it("ssl_verify=false の設定が温めたキャッシュを ssl_verify=true の設定は共有しない", function()
      -- (a) ssl_verify=false（このスペックの既定 conf）で温める
      assert.is_truthy(jwt_validator.validate(conf, make()))
      local calls_after_warmup = http_call_count

      -- (b) ssl_verify だけを true に変えた設定は別キーで自分のエントリをロードする
      --     （HTTP 取得が増える）ため、TLS 検証なしで取得された鍵を再利用しない
      local strict_conf = {}
      for k, v in pairs(conf) do strict_conf[k] = v end
      strict_conf.ssl_verify = true

      local claims, err = jwt_validator.validate(strict_conf, make())
      assert.is_nil(err)
      assert.is_truthy(claims)
      assert.is_true(http_call_count > calls_after_warmup)
    end)
  end)
end)
