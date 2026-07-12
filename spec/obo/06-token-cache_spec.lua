-- 交換済みトークンキャッシュのテスト
-- kong.cache（実体は mlcache）をテーブルで簡易に模倣し、
-- 「キー設計」「TTL 計算」「ミス時のみ交換」「エラーを負キャッシュしない」ことを検証する

describe("obo: token_cache (unit)", function()
  local token_cache
  local conf
  local cache_store     -- 簡易キャッシュの実体: key → { value = v, ttl = t }
  local exchange_calls  -- exchange_fn の呼び出し回数

  setup(function()
    _G.kong = {
      log = { debug = function() end, err = function() end },
      cache = {
        -- mlcache 風の get: キャッシュにあれば返し、なければコールバックを実行して
        -- (value, err, ttl) を受け取り保存する
        get = function(_, key, _, cb, ...)
          local entry = cache_store[key]
          if entry then return entry.value end
          local value, err, ttl = cb(...)
          -- 実 mlcache の契約を忠実に模倣する:
          --   コールバックが (nil, err) を返した場合 → 何もキャッシュせずエラーを伝搬
          --   コールバックが (nil, nil) を返した場合 → nil が負キャッシュされる
          -- これにより「失敗を負キャッシュしない」要件の回帰をこのモックで検出できる
          if err ~= nil then
            return nil, err
          end
          cache_store[key] = { value = value, ttl = ttl }
          return value
        end,
        invalidate = function(_, key) cache_store[key] = nil end,
      },
    }
    token_cache = require("kong.plugins.obo.token_cache")
  end)

  teardown(function()
    _G.kong = nil
    package.loaded["kong.plugins.obo.token_cache"] = nil
  end)

  before_each(function()
    cache_store = {}
    exchange_calls = 0
    conf = {
      token_cache_enabled = true,
      cache_ttl_margin = 30,
      client_id = "client-a",
      scopes = { "api://x/.default" },
      tenant_id = "tenant-a",
      identity_base_url = "https://mock-idp.example",
    }
  end)

  -- 成功する exchange_fn を作るテスト用ローカル関数
  local function ok_exchange(token_value, expires_in)
    return function()
      exchange_calls = exchange_calls + 1
      return { access_token = token_value, expires_in = expires_in }
    end
  end

  it("キャッシュミス時に exchange_fn を呼び、その access_token を返す", function()
    local token, err = token_cache.get(conf, "incoming", ok_exchange("exchanged", 3600))
    assert.is_nil(err)
    assert.equal("exchanged", token)
    assert.equal(1, exchange_calls)
  end)

  it("2 回目はキャッシュから返し exchange_fn を呼ばない", function()
    token_cache.get(conf, "incoming", ok_exchange("exchanged", 3600))
    local token = token_cache.get(conf, "incoming", ok_exchange("other", 3600))
    assert.equal("exchanged", token)
    assert.equal(1, exchange_calls)
  end)

  it("受信トークンが違えば別キャッシュになる", function()
    token_cache.get(conf, "incoming-1", ok_exchange("t1", 3600))
    token_cache.get(conf, "incoming-2", ok_exchange("t2", 3600))
    assert.equal(2, exchange_calls)
  end)

  -- tenant_id をキー材料に含めないと、同じ受信トークン・client_id・scopes で
  -- テナントだけが違う設定を使い回した場合に別テナント向けの交換済みトークンを誤って
  -- キャッシュヒットさせてしまう危険がある
  it("tenant_id が違えば別キャッシュになる（同一トークン・client_id・scopes でも）", function()
    token_cache.get(conf, "incoming", ok_exchange("t-tenant-a", 3600))
    local other_conf = {}
    for k, v in pairs(conf) do other_conf[k] = v end
    other_conf.tenant_id = "tenant-b"
    token_cache.get(other_conf, "incoming", ok_exchange("t-tenant-b", 3600))
    assert.equal(2, exchange_calls)
  end)

  -- identity_base_url（テナントを識別する IdP のベース URL）が違う場合も同様に別キャッシュとする
  it("identity_base_url が違えば別キャッシュになる（同一トークン・client_id・scopes でも）", function()
    token_cache.get(conf, "incoming", ok_exchange("t-idp-a", 3600))
    local other_conf = {}
    for k, v in pairs(conf) do other_conf[k] = v end
    other_conf.identity_base_url = "https://other-idp.example"
    token_cache.get(other_conf, "incoming", ok_exchange("t-idp-b", 3600))
    assert.equal(2, exchange_calls)
  end)

  it("キャッシュキーに生の受信トークンを含めない（ハッシュ化されている）", function()
    token_cache.get(conf, "super-secret-incoming-token", ok_exchange("t", 3600))
    for key in pairs(cache_store) do
      assert.is_nil(key:find("super-secret-incoming-token", 1, true))
    end
  end)

  it("TTL は expires_in - cache_ttl_margin になる", function()
    token_cache.get(conf, "incoming", ok_exchange("t", 3600))
    local _, entry = next(cache_store)
    assert.equal(3600 - 30, entry.ttl)
  end)

  it("expires_in が margin 以下でも TTL は最低 1 秒になる", function()
    token_cache.get(conf, "incoming", ok_exchange("t", 10))
    local _, entry = next(cache_store)
    assert.equal(1, entry.ttl)
  end)

  it("token_cache_enabled=false なら毎回 exchange_fn を呼ぶ", function()
    conf.token_cache_enabled = false
    token_cache.get(conf, "incoming", ok_exchange("t", 3600))
    token_cache.get(conf, "incoming", ok_exchange("t", 3600))
    assert.equal(2, exchange_calls)
    assert.same({}, cache_store)  -- キャッシュには何も入らない
  end)

  it("exchange_fn の失敗はキャッシュされず、エラーがそのまま返る", function()
    local fail_exchange = function()
      exchange_calls = exchange_calls + 1
      return nil, { status = 502, error = "idp_unreachable" }
    end
    local token, err = token_cache.get(conf, "incoming", fail_exchange)
    assert.is_nil(token)
    assert.equal(502, err.status)
    assert.same({}, cache_store)  -- 失敗を負キャッシュしないこと

    -- 次の呼び出しでは再度 exchange が試行される
    token_cache.get(conf, "incoming", ok_exchange("recovered", 3600))
    assert.equal(2, exchange_calls)
  end)
end)
