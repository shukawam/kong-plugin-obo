-- obo プラグインのハンドラー（オーケストレーション）
-- 処理の流れ（設計書 docs/superpowers/specs/2026-07-10-obo-plugin-design.md §1）:
--   ① Authorization ヘッダーから Bearer トークンを抽出
--   ② jwt_validator で検証（署名・iss・aud・exp・nbf）
--   ③ token_cache 経由で交換済みトークンを取得（ミス時は token_exchange が実行される）
--   ④ upstream への Authorization を交換後トークンに差し替え

local jwt_validator  = require "kong.plugins.obo.jwt_validator"
local token_exchange = require "kong.plugins.obo.token_exchange"
local token_cache    = require "kong.plugins.obo.token_cache"

local plugin = {
  -- PRIORITY はプラグインの実行順序を決める（大きいほど先）。
  -- 認証系として一般的な位置の 1000 を使う
  PRIORITY = 1000,
  VERSION = "0.1.0",
}

-- Authorization ヘッダーから Bearer トークンを取り出すローカル関数
-- @return トークン文字列。Bearer 形式でなければ nil
local function extract_bearer_token()
  local auth = kong.request.get_header("Authorization")
  if type(auth) ~= "string" then
    return nil
  end
  -- "Bearer <token>" 形式にマッチさせる（大文字小文字の揺れを許容）
  return auth:match("^[Bb][Ee][Aa][Rr][Ee][Rr]%s+(%S+)%s*$")
end

-- 401 を返す共通処理
-- 内部的な失敗理由はレスポンスに含めず debug ログにのみ出す（情報漏えい防止）
-- @param reason 内部ログ用の理由
-- @param www_authenticate WWW-Authenticate ヘッダーの値（省略時は realm のみ）
local function unauthorized(reason, www_authenticate)
  kong.log.debug("obo: unauthorized: ", reason)
  return kong.response.exit(401, { message = "Unauthorized" }, {
    ["WWW-Authenticate"] = www_authenticate or 'Bearer realm="kong"',
  })
end

function plugin:access(conf)
  -- ① Bearer トークン抽出
  local token = extract_bearer_token()
  if not token then
    return unauthorized("missing or non-bearer Authorization header")
  end

  -- ② 受信トークンの検証
  local claims, validate_err = jwt_validator.validate(conf, token)
  if not claims then
    return unauthorized(validate_err, 'Bearer error="invalid_token"')
  end

  -- ③ 交換済みトークンの取得（キャッシュミス時のみ Entra ID へ交換リクエスト）
  local access_token, exchange_err = token_cache.get(conf, token, function()
    return token_exchange.exchange(conf, token)
  end)

  if not access_token then
    local err = type(exchange_err) == "table" and exchange_err or {}
    kong.log.debug("obo: token exchange failed: ", err.error or "unknown",
                   " ", err.detail or "")

    if err.status == 401 then
      -- Entra のエラーとクレームチャレンジは WWW-Authenticate で伝搬する（docs/obo/03）。
      -- claims は JSON（引用符を含む）なので Base64 にしてから載せる
      local www = 'Bearer error="' .. (err.error or "invalid_token") .. '"'
      if err.claims then
        www = www .. ', claims="' .. ngx.encode_base64(err.claims) .. '"'
      end
      return unauthorized("idp rejected the token exchange", www)
    end

    if err.status == 502 then
      return kong.response.exit(502, { message = "Bad Gateway" })
    end
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end

  -- ④ upstream への Authorization を交換後トークンに差し替える。
  --    受信トークンを upstream に流さないことが重要（docs/obo/02 の Warning:
  --    middle-tier 宛てトークンを他所へ送ってはならない）
  kong.service.request.set_header("Authorization", "Bearer " .. access_token)
end

return plugin
