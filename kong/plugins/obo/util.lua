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
-- @param tenant_id テナント ID（GUID）
-- @param path 連結する残りのパス（先頭スラッシュなし。省略時は {base}/{tenant} まで）
--             例: "v2.0/.well-known/openid-configuration" / "oauth2/v2.0/token" / "v2.0"
-- @return 連結済み URL 文字列
function M.build_tenant_url(base, tenant_id, path)
  -- 末尾のスラッシュを（複数連続していても）まとめて 1 個も残さず除去する。
  -- gsub は (置換後文字列, 置換回数) を返すため括弧で 1 値に絞る
  base = (base:gsub("/+$", ""))
  local url = base .. "/" .. tenant_id
  if path and path ~= "" then
    url = url .. "/" .. path
  end
  return url
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

return M
