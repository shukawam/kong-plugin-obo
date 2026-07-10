-- 交換済みトークンのキャッシュ
-- リクエストのたびに Entra ID へ交換リクエストを送るとレイテンシーとレート制限の問題が
-- 出るため、受信トークン（のハッシュ）をキーに交換済みトークンを kong.cache に保持する。
-- TTL は交換レスポンスの expires_in から余裕幅（cache_ttl_margin）を引いた値。

local resty_sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex

local M = {}

-- SHA-256 の 16 進ダイジェストを返すローカル関数
local function sha256_hex(s)
  local digest = resty_sha256:new()
  digest:update(s)
  return to_hex(digest:final())
end

-- キャッシュキーを作るローカル関数
-- 生のトークンをキーにしない（共有メモリに平文トークンを並べないため）。
-- client_id と scopes もキーに含め、設定変更後に古いトークンを引かないようにする
local function cache_key(conf, incoming_token)
  local material = incoming_token .. "|" .. conf.client_id .. "|" .. table.concat(conf.scopes, " ")
  return "obo:token:" .. sha256_hex(material)
end

-- 交換済みトークンを取得する。キャッシュミス時のみ exchange_fn を呼ぶ
-- @param conf プラグイン設定
-- @param incoming_token 受信アクセストークン（キャッシュキーの材料）
-- @param exchange_fn 引数なしで (res, err) を返す関数（token_exchange.exchange と同じ契約）
-- @return 交換後アクセストークン文字列。失敗時は nil と exchange_fn のエラー
function M.get(conf, incoming_token, exchange_fn)
  -- キャッシュ無効時は素通しで毎回交換する
  if not conf.token_cache_enabled then
    local res, err = exchange_fn()
    if not res then
      return nil, err
    end
    return res.access_token
  end

  -- コールバック内で起きたエラーの詳細（テーブル）を持ち出すための変数。
  -- kong.cache のエラー伝搬は文字列化される可能性があるため、この方式で確実に取り出す
  local exchange_err

  local token, cache_err = kong.cache:get(cache_key(conf, incoming_token), nil, function()
    local res, err = exchange_fn()
    if not res then
      exchange_err = err
      -- (nil, err) を返すとキャッシュされずにエラーが伝搬する（負キャッシュを防ぐ）
      return nil, "exchange failed"
    end
    -- 第 3 戻り値が TTL になる（mlcache の仕様）。期限切れ間際を避けるため margin を引く
    local ttl = math.max((tonumber(res.expires_in) or 0) - conf.cache_ttl_margin, 1)
    return res.access_token, nil, ttl
  end)

  if exchange_err then
    return nil, exchange_err
  end
  if not token then
    -- exchange 以外の失敗（キャッシュ層自体の異常）
    return nil, { status = 500, error = "cache_failure", detail = tostring(cache_err) }
  end
  return token
end

return M
