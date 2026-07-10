-- Entra ID への On-Behalf-Of トークン交換リクエスト
-- 仕様: docs/obo/02-token-request.md（リクエスト形式）, docs/obo/03-token-response.md（レスポンス解釈）

local http  = require "resty.http"
local cjson = require "cjson.safe"
local client_assertion = require "kong.plugins.obo.client_assertion"

local M = {}

-- RFC 7523 で定義された固定 URN（docs/obo/02, 07）
local GRANT_TYPE_JWT_BEARER   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
local CLIENT_ASSERTION_TYPE   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

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

  -- Entra のエラー JSON（error フィールドあり）: 受信トークンが交換できない状態
  -- （interaction_required 等）。middle-tier は 401 で伝搬する（docs/obo/03）
  if type(json) == "table" and type(json.error) == "string" then
    return nil, {
      status = res.status >= 500 and 502 or 401,
      error  = json.error,
      claims = type(json.claims) == "string" and json.claims or nil,
      detail = json.error_description,  -- 内部ログ専用。レスポンスに出さないこと
    }
  end

  -- JSON ですらない・想定外の形 → IdP 側の異常として 502
  return nil, { status = 502, error = "invalid_idp_response", detail = "status " .. res.status }
end

return M
