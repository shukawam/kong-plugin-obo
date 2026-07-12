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

  -- 設計書（docs/superpowers/specs/2026-07-10-obo-plugin-design.md §5）のエラーマッピングでは
  -- 「受信 JWT の検証失敗（署名・iss・aud・exp）→ 401」と「Entra ID への接続失敗 / 5xx → 502」を
  -- 区別している。JWKS の取得は Entra ID への接続そのものなので、取得に失敗した場合は
  -- 「トークンが不正」（401 相当）ではなく「IdP に接続できない」（502 相当）として
  -- 呼び出し元（handler）が区別できる必要がある。この区別のための第 3 戻り値を検証する。
  it("IdP に接続できない場合は upstream（IdP 到達不能）エラーとして返す（3 番目の戻り値）", function()
    http_responses = {}  -- 全 URL で connection refused
    local claims, err, is_upstream_error = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  it("openid-configuration が不正な形（jwks_uri 欠落）でも upstream エラーとして返す", function()
    http_responses["https://mock-idp.example/test-tenant/v2.0/.well-known/openid-configuration"].body =
      cjson.encode({ issuer = "x" })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  it("JWKS に存在しない kid（IdP 自体は正常応答）は upstream エラーにしない（401 のまま）", function()
    local token = jwt.make(nil, { kid = "unknown-key" })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, token)
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_falsy(is_upstream_error)
  end)

  it("署名が不正なトークンは upstream エラーにしない（401 のまま）", function()
    local token = jwt.make()
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
    http_responses["https://mock-idp.example/test-tenant/discovery/v2.0/keys"].body =
      cjson.encode({ keys = { { kty = "RSA", kid = keys.kid, n = "!!!", e = "!!!" } } })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- Fix 1: 未知 kid による JWKS 再取得のデバウンス。
  -- kong.cache のモックは素通し（毎回コールバック実行）のため、実キャッシュの有無に関わらず
  -- 「無効化 + 再取得」のもう一往復が抑止されることを HTTP 呼び出し回数の差分で検証する。
  -- last_refetch はモジュール state なので、他テストの影響を受けないよう describe 内で
  -- 都度モジュールを再 require してリセットする
  describe("未知 kid の再取得デバウンス", function()
    before_each(function()
      package.loaded["kong.plugins.obo.jwt_validator"] = nil
      jwt_validator = require("kong.plugins.obo.jwt_validator")
    end)

    it("同一ワーカー内で連続する未知 kid は 2 回目の再取得（無効化+再取得）を抑止する", function()
      local token = jwt.make(nil, { kid = "unknown-key" })

      local claims1, err1 = jwt_validator.validate(conf, token)
      assert.is_nil(claims1)
      assert.is_string(err1)
      local calls_after_first = http_call_count

      local claims2, err2 = jwt_validator.validate(conf, token)
      assert.is_nil(claims2)
      assert.is_string(err2)
      local calls_after_second = http_call_count

      -- kong.cache モックは素通し（毎回コールバック実行）なので、1 回の validate で
      -- 「通常の取得」と「無効化後の再取得」の 2 往復（openid-config + jwks 各 2 回）= 4 回になる。
      -- デバウンスされていれば 2 回目は「通常の取得」の 2 回だけで、再取得の 2 回は発生しない。
      assert.equal(4, calls_after_first)
      assert.equal(2, calls_after_second - calls_after_first)
    end)
  end)
end)
