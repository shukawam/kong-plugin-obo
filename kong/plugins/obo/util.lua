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

return M
