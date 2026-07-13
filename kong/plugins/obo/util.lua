-- Base64URL エンコード/デコード（RFC 7515 で JWT が使う形式）
-- 通常の Base64 との違い: "+"→"-", "/"→"_" の置換と、末尾パディング "=" の省略

local M = {}

-- 文字列を Base64URL にエンコードする
-- @param s エンコードする文字列（バイナリ可）
-- @return Base64URL 文字列
function M.b64url_encode(s)
  -- ngx.encode_base64 の第 2 引数 true は「パディングを付けない」指定
  local b64 = ngx.encode_base64(s, true)
  -- gsub は (置換後文字列, 置換回数) の 2 値を返すため、括弧で 1 値に絞る
  return (b64:gsub("+", "-"):gsub("/", "_"))
end

-- Base64URL 文字列をデコードする
-- @param s Base64URL 文字列
-- @return デコード結果。不正な入力なら nil
function M.b64url_decode(s)
  if type(s) ~= "string" then
    return nil
  end
  s = s:gsub("-", "+"):gsub("_", "/")
  -- 省略されたパディングを復元する（長さを 4 の倍数に揃える）
  local rem = #s % 4
  if rem == 2 then
    s = s .. "=="
  elseif rem == 3 then
    s = s .. "="
  elseif rem == 1 then
    return nil  -- 長さ 4n+1 の Base64 は存在しない
  end
  return ngx.decode_base64(s)
end

-- テナント固有の URL / issuer を組み立てる共通関数。
-- Entra ID の各エンドポイント（メタデータ・JWKS・トークン）と issuer は
-- いずれも {identity_base_url}/{tenant_id}/... の形をとる。この連結を 1 箇所に集約し、
-- identity_base_url の末尾スラッシュをここで正規化することで、設定に末尾スラッシュが
-- 付いていても issuer が "...//tenant/v2.0" のように壊れることを防ぐ。
-- @param base identity_base_url（例: "https://login.microsoftonline.com"。末尾 "/" 付き可）
-- @param tenant_id テナント ID（GUID またはドメイン名）。小文字に正規化される（下記コメント参照）
-- @param path 連結する残りのパス（先頭スラッシュなし。省略時は {base}/{tenant} まで）
--             例: "v2.0/.well-known/openid-configuration" / "oauth2/v2.0/token" / "v2.0"
-- @return 連結済み URL 文字列。base / tenant_id が文字列でなければ nil とエラー理由
function M.build_tenant_url(base, tenant_id, path)
  -- 規約（エラーは nil, err の 2 値返し）に従い、不正な型では例外を投げず nil を返す。
  -- スキーマで required になっているため通常は到達しない防御的ガード
  if type(base) ~= "string" or type(tenant_id) ~= "string" then
    return nil, "base and tenant_id must be strings"
  end
  -- 末尾のスラッシュを（複数連続していても）まとめて 1 個も残さず除去する。
  -- gsub は (置換後文字列, 置換回数) を返すため括弧で 1 値に絞る
  base = (base:gsub("/+$", ""))
  -- tenant_id を小文字に正規化する。Entra ID のメタデータは、大文字 GUID で
  -- 要求しても issuer 内の GUID を小文字で返す（実メタデータで裏取り済み）ため、
  -- 大文字のまま導出すると metadata issuer の完全一致検証が常に失敗してしまう。
  -- GUID の 16 進表記は大文字小文字の区別を持たず、ドメイン名（contoso.onmicrosoft.com 等）も
  -- DNS が大文字小文字を区別しないため、どちらの形式でも小文字化は同じテナントを指す
  local url = base .. "/" .. tenant_id:lower()
  if path and path ~= "" then
    url = url .. "/" .. path
  end
  return url
end

-- GUID（8-4-4-4-12 桁の 16 進）の Lua パターン。%x は大文字小文字どちらの 16 進にも
-- マッチする。schema（tenant_id の形式検証）と jwt_validator（issuer の形式検証）で共用する
M.GUID_PATTERN =
  "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"

-- 文字列が GUID かどうかを判定する（大文字小文字は問わない）
-- @param s 判定対象
-- @return boolean
function M.is_guid(s)
  -- match は不一致で nil を返すため、~= nil で必ず boolean に揃える
  return type(s) == "string" and s:match(M.GUID_PATTERN) ~= nil
end

-- 絶対 URL から scheme と authority（host[:port]）を取り出す。
-- jwks_uri の scheme（HTTPS 要求）と host（identity_base_url と一致するか）の検証に使う。
-- @param url 検証対象の URL 文字列
-- @return scheme（小文字）, authority。絶対 URL でなければ nil
function M.url_scheme_authority(url)
  if type(url) ~= "string" then
    return nil
  end
  -- "scheme://authority/..." の scheme と authority（次の "/" までの host:port）を取る
  local scheme, authority = url:match("^(%a[%w+.-]*)://([^/]+)")
  if not scheme then
    return nil
  end
  return scheme:lower(), authority
end

-- ログに出力する文字列の既定の上限長（文字数）。
-- IdP（Entra ID）の error_description は数百文字に及ぶことがあるため、
-- ログ集約基盤を肥大化させない程度の長さに抑える
local DEFAULT_LOG_VALUE_MAX_LEN = 256

-- 外部（IdP のエラーレスポンスや、クライアントが送ってきた JWT のヘッダーなど）由来の
-- 文字列を debug ログに出す前に無害化するローカル関数（Issue #9）。
--
-- 何をなぜ無害化するか:
--   ・CR/LF を含む制御文字（0x00-0x1F, 0x7F）を空白 1 文字に置換する。
--     これらをそのままログに書くと、1 回の呼び出しが複数行のログとして解釈され、
--     あたかも別の（偽の）ログ行が追加されたように見える「ログインジェクション」を
--     引き起こしうる。空白に置換することで見た目上 1 行に保つ。
--   ・長さを上限（既定 256 文字）で切り詰める。IdP のエラーメッセージには
--     ユーザーの UPN やメールアドレス等の PII が混ざることがあり、また巨大な
--     文字列は単純にログ集約基盤を圧迫する。切り詰めにより影響を限定する。
-- @param value 無害化したい値。文字列以外（nil・数値・テーブル等）は空文字を返す
-- @param max_len 切り詰める上限長（省略時は 256 文字）
-- @return 無害化後の文字列
function M.sanitize_log_value(value, max_len)
  if type(value) ~= "string" then
    return ""
  end
  max_len = max_len or DEFAULT_LOG_VALUE_MAX_LEN

  -- Lua パターンの %z は埋め込み NUL（\0）を表す（Lua 5.1 の文字列は \0 を含みうるため）。
  -- \1-\31 は残りの C0 制御文字、127 は DEL。まとめて空白に置換する
  local sanitized = value:gsub("[%z\1-\31\127]", " ")

  if #sanitized > max_len then
    sanitized = sanitized:sub(1, max_len)
  end
  return sanitized
end

return M
