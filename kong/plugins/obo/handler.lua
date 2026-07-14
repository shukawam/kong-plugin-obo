-- obo プラグインのハンドラー（オーケストレーション）
-- 処理の流れ（設計書 docs/superpowers/specs/2026-07-10-obo-plugin-design.md §1）:
--   ①  Authorization ヘッダーから Bearer トークンを抽出
--   ②  jwt_validator で認証（署名・iss・aud・exp・nbf）
--   ②' scope_validator で認可（required_scopes / required_roles の scp / roles 検査。
--       権限不足は 403 insufficient_scope、未設定なら検査なし）
--   ③  token_cache 経由で交換済みトークンを取得（ミス時は token_exchange が実行される）
--   ④  upstream への Authorization を交換後トークンに差し替え

local jwt_validator   = require "kong.plugins.obo.jwt_validator"
local scope_validator = require "kong.plugins.obo.scope_validator"
local token_exchange  = require "kong.plugins.obo.token_exchange"
local token_cache     = require "kong.plugins.obo.token_cache"
local util            = require "kong.plugins.obo.util"

local plugin = {
  -- PRIORITY はプラグインの実行順序を決める（大きいほど先）。
  -- 認証系として一般的な位置の 1000 を使う
  PRIORITY = 1000,
  VERSION = "0.2.1",
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

-- WWW-Authenticate ヘッダーに埋め込むエラー識別子を無害化するローカル関数
-- IdP のレスポンス由来の値をそのまま埋め込むとヘッダーインジェクションの恐れがあるため、
-- OAuth のエラーコードに現れる文字（英数字と - _ .）だけを許可し、それ以外は既定値に落とす
local function sanitize_error_code(value)
  if type(value) ~= "string" or value == "" or value:find("[^%w%-%_%.]") then
    return "invalid_token"
  end
  return value
end

-- 401 を返す共通処理
-- 内部的な失敗理由はレスポンスに含めず debug ログにのみ出す（情報漏えい防止）
-- @param reason 内部ログ用の理由
-- @param www_authenticate WWW-Authenticate ヘッダーの値（省略時は realm のみ）
local function unauthorized(reason, www_authenticate)
  -- reason には受信 JWT のヘッダー値（alg 等、クライアント制御下）に由来する文字列が
  -- 含まれることがあるため、ログに出す前に無害化する（Issue #9）
  kong.log.debug("obo: unauthorized: ", util.sanitize_log_value(reason))
  return kong.response.exit(401, { message = "Unauthorized" }, {
    ["WWW-Authenticate"] = www_authenticate or 'Bearer realm="kong"',
  })
end

-- 403 を返す共通処理（認証は成功したが権限が不足しているケース）。
-- RFC 6750 §3.1 は「必要な権限より低いトークン」を insufficient_scope と定義し、
-- §3 で 403 Forbidden を SHOULD としている。401（認証失敗）とは明確に区別する。
-- 内部理由（どのスコープ/ロールが不足か）はレスポンスに含めず debug ログのみ。
local function forbidden(reason)
  -- reason は scope_validator が組み立てる内部文言だが、トークンのクレーム値
  -- （クライアント制御下）が含まれ得るため、他のログと同じ方針で無害化する（Issue #9）
  kong.log.debug("obo: forbidden: ", util.sanitize_log_value(reason))
  return kong.response.exit(403, { message = "Forbidden" }, {
    ["WWW-Authenticate"] = 'Bearer error="insufficient_scope"',
  })
end

function plugin:access(conf)
  -- ① Bearer トークン抽出
  local token = extract_bearer_token()
  if not token then
    return unauthorized("missing or non-bearer Authorization header")
  end

  -- ② 受信トークンの検証
  local claims, validate_err, validate_upstream_err = jwt_validator.validate(conf, token)
  if not claims then
    if validate_upstream_err then
      -- 受信トークンではなく Entra ID（OpenID configuration / JWKS）への接続・応答が
      -- 原因の失敗。「トークンが不正」（401）ではなく「IdP に到達できない」（502）として扱う
      -- （docs/superpowers/specs/2026-07-10-obo-plugin-design.md §5）
      kong.log.debug("obo: jwt validation failed due to upstream error: ",
                     util.sanitize_log_value(validate_err))
      return kong.response.exit(502, { message = "Bad Gateway" })
    end
    return unauthorized(validate_err, 'Bearer error="invalid_token"')
  end

  -- ②' 認可: required_scopes / required_roles を満たすか検査する。
  --     トークンは正当だが権限が足りない場合は 401 ではなく 403 insufficient_scope。
  --     required_* が未設定なら常に true（後方互換。認可を別プラグインに委ねる運用も可）
  local authorized, authz_err = scope_validator.authorize(conf, claims)
  if not authorized then
    return forbidden(authz_err)
  end

  -- ③ 交換済みトークンの取得（キャッシュミス時のみ Entra ID へ交換リクエスト）
  local access_token, exchange_err = token_cache.get(conf, token, function()
    return token_exchange.exchange(conf, token)
  end)

  if not access_token then
    local err = type(exchange_err) == "table" and exchange_err or {}
    -- err.detail（Entra の error_description）はユーザーの UPN・メールアドレス等の
    -- PII を含み得るため、ログには一切出力しない（Issue #9。切り詰めでも先頭部分に
    -- PII が残り得るため不十分）。トラブルシュートは error 識別子（OAuth エラーコード）と
    -- trace_id / correlation_id を Microsoft サポートや Entra のサインインログと
    -- 突合することで成立する。これらも外部由来の値なので念のため無害化してから出す
    kong.log.debug("obo: token exchange failed: error=", util.sanitize_log_value(err.error or "unknown"),
                   " trace_id=", util.sanitize_log_value(err.trace_id),
                   " correlation_id=", util.sanitize_log_value(err.correlation_id))

    if err.status == 401 then
      -- Entra のエラーとクレームチャレンジは WWW-Authenticate で伝搬する（docs/obo/03）。
      -- claims は JSON（引用符を含む）なので Base64 にしてから載せる
      local www = 'Bearer error="' .. sanitize_error_code(err.error) .. '"'
      if err.claims then
        www = www .. ', claims="' .. ngx.encode_base64(err.claims) .. '"'
      end
      return unauthorized("idp rejected the token exchange", www)
    end

    if err.status == 503 then
      -- レート制限 / 一時的なサービス不可（Issue #4）。Entra の Retry-After があれば透過する。
      -- 内部の error 識別子・詳細はレスポンスに含めない（debug ログのみ）
      local headers = {}
      if err.retry_after then
        headers["Retry-After"] = err.retry_after
      end
      return kong.response.exit(503, { message = "Service Unavailable" }, headers)
    end

    if err.status == 502 then
      return kong.response.exit(502, { message = "Bad Gateway" })
    end

    -- 設定・プロトコル起因（invalid_client 等）や想定外は汎用 500（Issue #4）。
    -- WWW-Authenticate を付けず、内部の失敗理由をレスポンスに出さない（誤誘導・情報漏えい防止）
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end

  -- ④ upstream への Authorization を交換後トークンに差し替える。
  --    受信トークンを upstream に流さないことが重要（docs/obo/02 の Warning:
  --    middle-tier 宛てトークンを他所へ送ってはならない）
  kong.service.request.set_header("Authorization", "Bearer " .. access_token)
end

return plugin
