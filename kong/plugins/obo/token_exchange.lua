-- Entra ID への On-Behalf-Of トークン交換リクエスト
-- 仕様: docs/obo/02-token-request.md（リクエスト形式）, docs/obo/03-token-response.md（レスポンス解釈）

local http  = require "resty.http"
local cjson = require "cjson.safe"
local client_assertion = require "kong.plugins.obo.client_assertion"

local M = {}

-- RFC 7523 で定義された固定 URN（docs/obo/02, 07）
local GRANT_TYPE_JWT_BEARER   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
local CLIENT_ASSERTION_TYPE   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

-- Entra のエラー JSON を HTTP ステータスへ分類する許可リスト（Issue #4）。
-- 変わり得る AADSTS 数値コード（error_codes）ではなく、安定した OAuth の error 文字列で分岐する。
-- 出典: RFC 6749 §5.2（token endpoint のエラー定義）, §4.1.2.1（temporarily_unavailable）,
--       docs/obo/03（Entra の interaction_required エラー例とクレームチャレンジ）。

-- ユーザー側で解決可能なエラー（受信トークンの取り直し・再対話で解消しうる）→ 401 + WWW-Authenticate
local USER_RESOLVABLE = {
  -- 条件付きアクセス（MFA 等）でユーザーの対話が必要。docs/obo/03 のエラー例そのもの
  interaction_required = true,
  -- 再ログインが必要（OpenID Connect）
  login_required       = true,
  -- 追加の同意が必要（OpenID Connect）
  consent_required     = true,
  -- RFC 6749 §5.2: authorization grant（= assertion に入れた受信トークン）が
  -- invalid/expired/revoked/失効。ユーザーが新しいトークンを取得すれば解消する
  invalid_grant        = true,
}

-- ゲートウェイ自身の設定・プロトコル起因（再認証しても解消しない）→ 500。
-- これらを 401 で返すと「あなたのトークンが不正」と誤誘導し、内部の設定不備を外部に示唆してしまう。
local CONFIG_ERROR = {
  -- RFC 6749 §5.2:「Client authentication failed」= プラグインの client_secret /
  -- client_assertion（クレデンシャル）の設定ミス。ユーザーのトークン起因ではない
  invalid_client         = true,
  -- RFC 6749 §5.2: 認証済みクライアントがこの grant_type を許可されていない（アプリ登録の設定）
  unauthorized_client    = true,
  -- RFC 6749 §5.2: 要求スコープが不正/未知/不正形式 = conf.scopes の設定ミス
  invalid_scope          = true,
  -- RFC 6749 §5.2: grant_type が未対応（プロトコル/設定の不整合）
  unsupported_grant_type = true,
  -- RFC 6749 §5.2: 必須パラメータ欠落や不正 = プラグインのリクエスト構築側の問題
  invalid_request        = true,
}

-- error 文字列を HTTP ステータスに分類するローカル関数。
-- @param code Entra のエラー JSON の error 文字列
-- @return 401（ユーザー解決可能） / 503（一時的） / 500（設定・未知）
local function classify_error(code)
  if USER_RESOLVABLE[code] then
    return 401
  end
  -- RFC 6749 §4.1.2.1:「一時的な過負荷またはメンテナンス」。再試行で解消しうる → 503
  if code == "temporarily_unavailable" then
    return 503
  end
  if CONFIG_ERROR[code] then
    return 500
  end
  -- 許可リストにない未知の error は、ユーザーのトークンを不当に「不正」扱い（401）せず、
  -- また内部詳細も出さない汎用サーバーエラー（500）として扱う（詳細は debug ログのみ）
  return 500
end

-- レスポンスヘッダーから Retry-After を安全に取り出すローカル関数。
-- Entra が付ける delta-seconds（秒数）だけを透過し、それ以外（不正な HTTP-date や
-- CRLF を含む値）は採用しない（レスポンスヘッダーインジェクション防止）。
-- @return 数字だけからなる文字列、または nil
local function safe_retry_after(headers)
  local v = headers and (headers["Retry-After"] or headers["retry-after"])
  -- lua-resty-http は同名ヘッダーが複数あるとテーブルで返すため先頭を採用する
  if type(v) == "table" then
    v = v[1]
  end
  if type(v) == "string" and v:match("^%d+$") then
    return v
  end
  return nil
end

-- テナント固有のトークンエンドポイント URL を組み立てる
function M.token_endpoint(conf)
  return conf.identity_base_url .. "/" .. conf.tenant_id .. "/oauth2/v2.0/token"
end

-- OBO トークン交換を実行する
-- @param conf プラグイン設定
-- @param incoming_token 検証済みの受信アクセストークン（assertion パラメータに入れる）
-- @return 成功: Entra のレスポンス JSON テーブル（access_token, expires_in など）
--         失敗: nil と err テーブル { status=HTTPステータス案, error=識別子, detail=内部ログ用, claims=クレームチャレンジ? }
function M.exchange(conf, incoming_token)
  local endpoint = M.token_endpoint(conf)

  -- リクエストボディ（docs/obo/02 の必須パラメータ）
  local body = {
    grant_type = GRANT_TYPE_JWT_BEARER,
    client_id = conf.client_id,
    assertion = incoming_token,
    scope = table.concat(conf.scopes, " "),  -- スペース区切りで連結
    requested_token_use = "on_behalf_of",
  }

  -- クライアント認証: client_secret または client_assertion（docs/obo/02 ケース1/2）
  if conf.client_auth_method == "client_secret" then
    body.client_secret = conf.client_secret
  else
    local assertion_jwt, err = client_assertion.build(conf, endpoint)
    if not assertion_jwt then
      return nil, { status = 500, error = "client_assertion_failed", detail = err }
    end
    body.client_assertion_type = CLIENT_ASSERTION_TYPE
    body.client_assertion = assertion_jwt
  end

  local client = http.new()
  client:set_timeout(conf.http_timeout)
  local res, req_err = client:request_uri(endpoint, {
    method = "POST",
    body = ngx.encode_args(body),
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    ssl_verify = conf.ssl_verify,
  })

  if not res then
    -- 接続レベルの失敗（DNS・タイムアウト・接続拒否など）→ 502 相当
    return nil, { status = 502, error = "idp_unreachable", detail = tostring(req_err) }
  end

  local json = cjson.decode(res.body)

  -- 成功: 200 かつ access_token がある場合のみ（docs/obo/03）
  if res.status == 200 and type(json) == "table" and type(json.access_token) == "string" then
    return json
  end

  -- HTTP 429（レート制限）: ボディの error 文字列に依らず 503 + Retry-After（透過）。
  -- Entra が付けた Retry-After（delta-seconds）があればクライアントへそのまま伝える
  if res.status == 429 then
    return nil, {
      status = 503,
      error = "temporarily_unavailable",
      retry_after = safe_retry_after(res.headers),
      detail = "http 429",
    }
  end

  -- HTTP 5xx: IdP 側の障害。ボディの error 文字列より優先して 502 に分類する
  if res.status >= 500 then
    return nil, { status = 502, error = "idp_error", detail = "status " .. res.status }
  end

  -- Entra のエラー JSON（error フィールドあり）を許可リストで分類する（Issue #4）
  if type(json) == "table" and type(json.error) == "string" then
    local status = classify_error(json.error)
    local err = {
      status = status,
      error  = json.error,
      detail = json.error_description,  -- 内部ログ専用。レスポンスに出さないこと
    }
    if status == 401 then
      -- クレームチャレンジは 401 の場合のみ handler が WWW-Authenticate に載せる（docs/obo/03）
      err.claims = type(json.claims) == "string" and json.claims or nil
    elseif status == 503 then
      -- temporarily_unavailable に Retry-After が付いていれば透過する
      err.retry_after = safe_retry_after(res.headers)
    end
    return nil, err
  end

  -- JSON ですらない・想定外の形 → IdP 側の異常として 502
  return nil, { status = 502, error = "invalid_idp_response", detail = "status " .. res.status }
end

return M
