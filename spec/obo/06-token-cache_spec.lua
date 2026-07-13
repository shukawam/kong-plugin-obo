-- 交換済みトークンキャッシュのテスト
-- kong.cache（実体は mlcache）をテーブルで簡易に模倣し、
-- 「キー設計」「TTL 計算」「ミス時のみ交換」「エラーを負キャッシュしない」ことを検証する

describe("obo: token_cache (unit)", function()
  local token_cache
  local conf
  local cache_store     -- 簡易キャッシュの実体: key → { value = v, ttl = t, stale = bool }
  local exchange_calls  -- exchange_fn の呼び出し回数
  local last_get_opts   -- 直近の kong.cache:get 呼び出しで渡された opts（第 2 引数）

  setup(function()
    _G.kong = {
      log = { debug = function() end, err = function() end },
      cache = {
        -- mlcache 風の get: キャッシュにあれば返し、なければコールバックを実行して
        -- (value, err, ttl) を受け取り保存する
        get = function(_, key, opts, cb, ...)
          last_get_opts = opts
          local entry = cache_store[key]
          if entry then
            if entry.stale then
              -- 実 mlcache が「期限切れ値を resurrect した」場合の契約を模倣する:
              -- 値は返るがエラーは nil、第 3 戻り値（hit_lvl）が 4 になる
              -- （lua-resty-mlcache/init.lua の STALE_FLAG 経路 = hit_lvl 4）
              return entry.value, nil, 4
            end
            return entry.value
          end
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
    last_get_opts = nil
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

  -- expires_in の正規化・上限クランプのテスト（Issue #10）
  -- IdP の異常応答（非数値・NaN・無限大・負数・欠落・超過値）でも
  -- TTL が意図しない値（永続キャッシュ等）にならないことを確認する
  describe("expires_in の正規化と上限クランプ", function()
    -- expires_in を任意の値にした exchange_fn を作るローカル関数
    -- expires_in を渡さない（nil）ことで「欠落」ケースも表現できる
    local function exchange_with(expires_in)
      return function()
        exchange_calls = exchange_calls + 1
        return { access_token = "t", expires_in = expires_in }
      end
    end

    it("expires_in が欠落（nil）していれば TTL は最低 1 秒になる", function()
      token_cache.get(conf, "incoming", exchange_with(nil))
      local _, entry = next(cache_store)
      assert.equal(1, entry.ttl)
    end)

    it("expires_in が非数値の文字列なら TTL は最低 1 秒になる", function()
      token_cache.get(conf, "incoming", exchange_with("not-a-number"))
      local _, entry = next(cache_store)
      assert.equal(1, entry.ttl)
    end)

    it("expires_in が NaN なら TTL は最低 1 秒になる", function()
      local nan = 0 / 0
      token_cache.get(conf, "incoming", exchange_with(nan))
      local _, entry = next(cache_store)
      assert.equal(1, entry.ttl)
    end)

    it("expires_in が無限大（inf）なら TTL は最低 1 秒になる", function()
      token_cache.get(conf, "incoming", exchange_with(math.huge))
      local _, entry = next(cache_store)
      assert.equal(1, entry.ttl)
    end)

    it("expires_in が負の無限大なら TTL は最低 1 秒になる", function()
      token_cache.get(conf, "incoming", exchange_with(-math.huge))
      local _, entry = next(cache_store)
      assert.equal(1, entry.ttl)
    end)

    it("expires_in が負数なら TTL は最低 1 秒になる", function()
      token_cache.get(conf, "incoming", exchange_with(-100))
      local _, entry = next(cache_store)
      assert.equal(1, entry.ttl)
    end)

    it("expires_in が数値文字列でも正しく解釈される", function()
      token_cache.get(conf, "incoming", exchange_with("3600"))
      local _, entry = next(cache_store)
      assert.equal(3600 - 30, entry.ttl)
    end)

    it("expires_in が上限（86400 秒）を超える巨大な有限値なら上限にクランプされる", function()
      token_cache.get(conf, "incoming", exchange_with(31536000)) -- 365 日
      local _, entry = next(cache_store)
      assert.equal(86400 - 30, entry.ttl)
    end)

    it("expires_in がちょうど上限（86400 秒）なら上限値そのまま使われる", function()
      token_cache.get(conf, "incoming", exchange_with(86400))
      local _, entry = next(cache_store)
      assert.equal(86400 - 30, entry.ttl)
    end)
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

  -- Issue #7: kong.cache は既定で期限切れ値を resurrect_ttl 秒（既定 30 秒）だけ
  -- 復活させる。resty.mlcache では resurrect_ttl は「stale 値を resurrect
  -- (復活) する猶予秒数」であり、そのまま lua_shared_dict の TTL としても使われる。
  -- ここで単純に 0 を指定すると、mlcache 自身の規約で「TTL=0 は無期限保存」を
  -- 意味してしまい、一度 resurrect された stale 値がむしろ恒久化する
  -- （実 mlcache で検証済み。Kong 本体の key-auth プラグインが resurrect_ttl に
  -- 0 ではなく 0.001 を使っているのも同じ理由）。そのため 0 より大きい極小の
  -- 値を明示的に渡すことを検証する
  it("kong.cache:get に resurrect_ttl として 0 ではなく極小の正の値を渡す", function()
    token_cache.get(conf, "incoming", ok_exchange("t", 3600))
    assert.is_table(last_get_opts)
    assert.equal("number", type(last_get_opts.resurrect_ttl))
    assert.is_true(last_get_opts.resurrect_ttl > 0)
    assert.is_true(last_get_opts.resurrect_ttl < 1)
  end)

  -- resurrect_ttl を極小値にしても、その一瞬の間に resurrect された stale 値を
  -- 拾ってしまう可能性はゼロではない（実 mlcache の resurrect 窓は ms 単位で残る）。
  -- そのため kong.cache:get の第 3 戻り値（hit_lvl）が 4（= stale 復活値）の場合は
  -- 明示的に失敗として扱い、期限切れの token B を絶対に返さないことを保証する
  it("hit_lvl が 4 (stale 復活値) の場合は失敗として扱い、期限切れの token を返さない", function()
    token_cache.get(conf, "incoming", ok_exchange("token-A", 3600))
    local key = next(cache_store)
    cache_store[key].stale = true  -- 次回 get で mlcache が stale 値を resurrect した状態を模倣

    local token, err = token_cache.get(conf, "incoming", ok_exchange("token-C", 3600))
    assert.is_nil(token)
    assert.is_not_nil(err)
  end)
end)

-- Issue #7 の実挙動再現テスト。
-- 単体テストのテーブルモックではなく、Kong 同梱の実 mlcache（kong.resty.mlcache）を
-- 直接使い、resurrect_ttl の実際の挙動（TTL 切れ + コールバック失敗時の resurrect）を
-- 検証する「半統合」テスト。busted 実行環境（kong-pongo）が既定で用意している
-- 共有辞書 kong_db_cache_2 をそのまま kong.cache の実体として使う
describe("obo: token_cache (semi-integration: 実 mlcache での resurrect_ttl 検証)", function()
  local mlcache = require "kong.resty.mlcache"
  local token_cache
  local conf
  local token_counter = 0

  setup(function()
    -- kong.cache 相当の薄いアダプタ。実装は kong/cache/init.lua の :get と同じ契約
    -- （mlcache:get をそのまま呼び、成否と hit_lvl（第 3 戻り値）を素通しする）。
    -- resurrect_ttl の既定値 30 は Kong 本体（kong/cache/init.lua）の既定と揃えてあり、
    -- token_cache.lua が呼び出し時に明示的に上書きしない限りこれが使われる
    local mlc = assert(mlcache.new("obo_test", "kong_db_cache_2", { resurrect_ttl = 30 }))
    _G.kong = {
      log = { debug = function() end, err = function() end },
      cache = {
        get = function(_, key, opts, cb, ...)
          local v, err, hit_lvl = mlc:get(key, opts, cb, ...)
          if err then
            return nil, err
          end
          return v, nil, hit_lvl
        end,
      },
    }
    token_cache = require("kong.plugins.obo.token_cache")
  end)

  teardown(function()
    _G.kong = nil
    package.loaded["kong.plugins.obo.token_cache"] = nil
  end)

  before_each(function()
    token_counter = token_counter + 1
    conf = {
      token_cache_enabled = true,
      cache_ttl_margin = 1,
      client_id = "client-real-cache-test",
      scopes = { "api://x/.default" },
      tenant_id = "tenant-real-cache-test",
      identity_base_url = "https://mock-idp.example",
    }
  end)

  -- テストごとに別の受信トークン（＝別キャッシュキー）を使い、
  -- 同じ共有辞書を使う他テストと状態が干渉しないようにする
  local function unique_token()
    return "resurrect-test-token-" .. tostring(token_counter) .. "-" .. tostring(ngx.now())
  end

  it("TTL 切れ直後に IdP 障害が起きても、直後（50ms 後）のリクエストが期限切れの token B を使い回さない", function()
    local incoming = unique_token()

    -- 1 回目: 成功。TTL は 1 秒（expires_in=2 - cache_ttl_margin=1）
    local token1, err1 = token_cache.get(conf, incoming, function()
      return { access_token = "token-A", expires_in = 2 }
    end)
    assert.is_nil(err1)
    assert.equal("token-A", token1)

    ngx.sleep(1.2)  -- TTL 切れを待つ

    -- 2 回目: この呼び出しが期限切れを検知し、ちょうど IdP 障害で失敗したケースを模す
    local token2, err2 = token_cache.get(conf, incoming, function()
      return nil, { status = 502, error = "idp_unreachable" }
    end)
    assert.is_nil(token2)
    assert.is_not_nil(err2)

    ngx.sleep(0.05)  -- 50ms 後（実運用でいう「その直後の別リクエスト」を模す）

    -- 3 回目: 50ms 前の障害から IdP が回復した状態を模す。exchange_fn が実際に呼ばれ、
    -- 新しい token-C が返るべき。resurrect_ttl が既定の 30 秒のままだと、ここで
    -- exchange_fn は一切呼ばれず、2 回目より前の古い token-A がそのまま返ってしまう
    -- （Issue #7 が指摘する stale resurrection の再現）
    local exchange3_calls = 0
    local token3, err3 = token_cache.get(conf, incoming, function()
      exchange3_calls = exchange3_calls + 1
      return { access_token = "token-C", expires_in = 3600 }
    end)
    assert.is_nil(err3)
    assert.equal(1, exchange3_calls)  -- exchange_fn が実際に呼ばれたこと（stale 値で素通りしていないこと）
    assert.equal("token-C", token3)   -- 期限切れの token-A ではなく新しい token-C が返ること
  end)
end)
