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
    -- 正常な OpenID 設定と JWKS を返すモック（形式は docs/obo/05 のメタデータ例に準拠）。
    -- issuer は取得元 authority（{identity_base_url}/{tenant_id}/v2.0）と一致させる（OIDC Discovery）
    http_responses = {
      ["https://mock-idp.example/test-tenant/v2.0/.well-known/openid-configuration"] = {
        status = 200,
        body = cjson.encode({
          issuer = "https://mock-idp.example/test-tenant/v2.0",
          jwks_uri = "https://mock-idp.example/test-tenant/discovery/v2.0/keys",
        }),
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

  -- 受け入れ条件: 末尾スラッシュ付き identity_base_url でも issuer 導出・メタデータ URL が
  -- 正しくなる（util.build_tenant_url による正規化の end-to-end 確認）。
  it("末尾スラッシュ付き identity_base_url でも issuer 導出・メタデータ URL が正しい", function()
    conf.identity_base_url = "https://mock-idp.example/"  -- 末尾スラッシュ付き
    conf.issuer = nil  -- 導出させる。正規化されず // になると iss/メタデータ取得が壊れる
    -- 正規化後の URL・issuer は末尾スラッシュなしと同一なので http_responses はそのまま通る
    local token = jwt.make({ iss = "https://mock-idp.example/test-tenant/v2.0" })
    local claims, err = jwt_validator.validate(conf, token)
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
      cjson.encode({ issuer = "https://mock-idp.example/test-tenant/v2.0" })
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
      cjson.encode({ issuer = "https://mock-idp.example/test-tenant/v2.0" })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- OIDC Discovery（openid-connect-discovery-1_0）: メタデータの issuer は取得元 authority と
  -- 完全一致しなければならない。一致しない場合は IdP 側メタデータの異常なので upstream エラー扱い。
  it("メタデータの issuer が期待値と一致しない場合は upstream エラーとして拒否する", function()
    http_responses["https://mock-idp.example/test-tenant/v2.0/.well-known/openid-configuration"].body =
      cjson.encode({
        issuer = "https://evil.example/test-tenant/v2.0",
        jwks_uri = "https://mock-idp.example/test-tenant/discovery/v2.0/keys",
      })
    local claims, err, is_upstream_error = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- jwks_uri のホストが identity_base_url と異なると、署名鍵を攻撃者ホストから取得させられる。
  -- OIDC メタデータの整合性違反として upstream エラー扱いで拒否する。
  it("jwks_uri のホストが identity_base_url と異なる場合は upstream エラーとして拒否する", function()
    http_responses["https://mock-idp.example/test-tenant/v2.0/.well-known/openid-configuration"].body =
      cjson.encode({
        issuer = "https://mock-idp.example/test-tenant/v2.0",
        jwks_uri = "https://evil.example/test-tenant/discovery/v2.0/keys",
      })
    -- 攻撃者ホストが正規の鍵で応答できても（署名検証自体は通る）ホスト不一致で拒否すること
    http_responses["https://evil.example/test-tenant/discovery/v2.0/keys"] = {
      status = 200,
      body = cjson.encode({ keys = { keys.jwk() } }),
    }
    local claims, err, is_upstream_error = jwt_validator.validate(conf, jwt.make())
    assert.is_nil(claims)
    assert.is_string(err)
    assert.is_truthy(is_upstream_error)
  end)

  -- identity_base_url が https のときは jwks_uri も https を要求する（平文での鍵取得を防ぐ）。
  it("jwks_uri が https でない場合は upstream エラーとして拒否する（identity_base_url が https）", function()
    http_responses["https://mock-idp.example/test-tenant/v2.0/.well-known/openid-configuration"].body =
      cjson.encode({
        issuer = "https://mock-idp.example/test-tenant/v2.0",
        jwks_uri = "http://mock-idp.example/test-tenant/discovery/v2.0/keys",
      })
    -- 平文 http でも鍵取得自体は成功しうるが、scheme 検証で拒否すること
    http_responses["http://mock-idp.example/test-tenant/discovery/v2.0/keys"] = {
      status = 200,
      body = cjson.encode({ keys = { keys.jwk() } }),
    }
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
      http_responses["https://mock-idp.example/test-tenant/discovery/v2.0/keys"] = function()
        jwks_seq = jwks_seq + 1
        if jwks_seq == 1 then
          return { status = 200, body = cjson.encode({ keys = { keys.jwk() } }) }
        end
        return { status = 200, body = cjson.encode({ keys = { keys.jwk(), rotated_jwk } }) }
      end

      local token = jwt.make(nil, { kid = new_kid })
      local claims, err = jwt_validator.validate(conf, token)

      assert.is_nil(err)
      assert.is_truthy(claims)
      assert.equal("test-user", claims.sub)
      -- 置換は renew（成功時のみ上書き）で行われ、クラスタ全体へ無効化イベントを配信する
      -- invalidate は一切呼ばれない（他ノードの正常キャッシュを消さないため）
      assert.equal(0, invalidate_count)

      -- 置換後は新 kid がキャッシュ済みなので、以後の同 kid は再取得せずに検証できる
      local calls_before = http_call_count
      local claims2 = jwt_validator.validate(conf, jwt.make(nil, { kid = new_kid }))
      assert.is_truthy(claims2)
      assert.equal(0, http_call_count - calls_before)
    end)

    it("再取得が失敗しても既存の JWKS キャッシュを失わない（stale 温存）", function()
      -- まず正常なトークンで JWKS（旧鍵 test-key-1）をキャッシュに載せる
      local ok_claims = jwt_validator.validate(conf, jwt.make())
      assert.is_truthy(ok_claims)
      assert.equal(0, invalidate_count)

      -- IdP を全断させる（openid-config も jwks も接続不可）
      http_responses = {}

      -- 未知 kid のトークンは再取得を試みるが、IdP 断で失敗する
      local claims, err, is_upstream =
        jwt_validator.validate(conf, jwt.make(nil, { kid = "test-key-2" }))
      assert.is_nil(claims)
      assert.is_string(err)
      -- IdP 到達不能は upstream エラー（502 相当）として返す
      assert.is_truthy(is_upstream)
      -- 取得失敗時は invalidate されない = 既存キャッシュが温存される
      assert.equal(0, invalidate_count)

      -- IdP は断のままでも、キャッシュ済みの旧鍵 test-key-1 のトークンは引き続き検証できる
      local claims2, err2 = jwt_validator.validate(conf, jwt.make())
      assert.is_nil(err2)
      assert.is_truthy(claims2)
    end)

    it("再投入（renew の書き込み）が失敗しても既存の JWKS キャッシュを失わない", function()
      -- まず正常なトークンで JWKS（旧鍵 test-key-1）をキャッシュに載せる
      assert.is_truthy(jwt_validator.validate(conf, jwt.make()))

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
        jwt_validator.validate(conf, jwt.make(nil, { kid = "test-key-2" }))
      assert.is_nil(claims)
      assert.is_string(err)
      -- 受信トークンの不正ではなくキャッシュ層の異常なので upstream エラー（502 経路）
      assert.is_truthy(is_upstream)
      -- invalidate は呼ばれず、既存キャッシュが温存される
      assert.equal(0, invalidate_count)

      -- 旧鍵 test-key-1 のトークンは引き続き検証できる（HTTP 再取得も不要 = キャッシュヒット）
      local calls_before = http_call_count
      assert.is_truthy(jwt_validator.validate(conf, jwt.make()))
      assert.equal(0, http_call_count - calls_before)
    end)

    -- Medium 2: 再取得が失敗した直後の抑止期間（30 秒デバウンス）中に来た未知 kid は、
    -- 「トークンが不正」（401）ではなく直前と同じ IdP 障害が続いているとみなして
    -- upstream エラー（502 経路）として分類すべき。誤分類だとクライアントに
    -- 「トークンを直せ」という誤ったシグナルを返してしまう
    it("再取得失敗後の抑止期間中の未知 kid は upstream エラー（502 経路）として返す", function()
      -- まず正常なトークンで JWKS（旧鍵 test-key-1）をキャッシュに載せる
      assert.is_truthy(jwt_validator.validate(conf, jwt.make()))

      -- IdP を全断させる
      http_responses = {}

      -- 1 回目の未知 kid: 再取得を試みて失敗 → upstream エラー
      local _, err1, up1 = jwt_validator.validate(conf, jwt.make(nil, { kid = "test-key-2" }))
      assert.is_string(err1)
      assert.is_truthy(up1)

      -- 2 回目（抑止期間中）: 再取得はデバウンスで抑止されるが、直前の失敗が
      -- 続いているとみなして upstream エラーとして返すこと
      local claims2, err2, up2 = jwt_validator.validate(conf, jwt.make(nil, { kid = "test-key-2" }))
      assert.is_nil(claims2)
      assert.is_string(err2)
      assert.is_truthy(up2)

      -- 回帰確認: 抑止期間中でも、キャッシュ済みの旧鍵 test-key-1 のトークンは検証成功する
      assert.is_truthy(jwt_validator.validate(conf, jwt.make()))
    end)

    it("再取得成功後の抑止期間中の未知 kid は upstream エラーにしない（401 のまま）", function()
      -- IdP は正常応答のまま。未知 kid → 再取得成功、しかし kid は本当に存在しない
      local _, err1, up1 = jwt_validator.validate(conf, jwt.make(nil, { kid = "no-such-kid" }))
      assert.is_string(err1)
      assert.is_falsy(up1)

      -- 抑止期間中の 2 回目も、直前の再取得は成功している（IdP は健在）ので 401 のまま
      local claims2, err2, up2 = jwt_validator.validate(conf, jwt.make(nil, { kid = "no-such-kid" }))
      assert.is_nil(claims2)
      assert.is_string(err2)
      assert.is_falsy(up2)
    end)
  end)
end)
