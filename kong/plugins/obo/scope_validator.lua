-- 受信アクセストークンの scp（委任スコープ）/ roles（アプリロール）による認可チェック
-- 仕様: docs/obo/05-token-validation.md（scp/roles の形式）、RFC 6750（insufficient_scope）
--
-- 認証（署名・iss・aud・exp）は jwt_validator が担当する。このモジュールは
-- 「トークンは有効だが、要求された権限を満たすか」だけを判定する（認可）。
-- 権限不足は RFC 6750 に従い、呼び出し元（handler）が 403 insufficient_scope として扱う。
--
-- クレームの形式（一次情報の裏取り済み）:
--   - scp:   スペース区切りのスコープ文字列。**ユーザートークンにのみ含まれる**
--            （Microsoft "Access token claims reference" の scp 行:
--             "String, a space separated list of scopes ... Only included for user tokens."）。
--            daemon / app-only / id_token では scp が存在しない
--            （"Secure applications and APIs by validating claims" > Validate the actor）。
--            → required_scopes を設定すると、scp 欠落トークン（app-only 等）は必然的に
--              「必須スコープ不足」となり拒否される。OBO はユーザープリンシパルのみ対象なので妥当。
--   - roles: 文字列の配列。app-only トークンにもユーザーの割当ロールにも使われるため、
--            「ユーザートークンかどうか」の判定には使わない（同 access-token-claims-reference roles 行）。

local M = {}

-- 値が「未設定」か（nil または Kong が optional 欠落を正規化した ngx.null）を判定するローカル関数
-- 既定値のない optional 配列は、省略時に nil ではなく ngx.null になるため両方を吸収する
local function is_unset(value)
  return value == nil or value == ngx.null
end

-- スペース区切りの scp 文字列を { scope = true } の集合に変換するローカル関数
-- 連続スペースや前後の空白は無視して非空白トークンだけを拾う
local function parse_scp(scp)
  local set = {}
  if type(scp) == "string" then
    for scope in scp:gmatch("%S+") do
      set[scope] = true
    end
  end
  return set
end

-- roles 配列を { role = true } の集合に変換するローカル関数
local function parse_roles(roles)
  local set = {}
  if type(roles) == "table" then
    for _, role in ipairs(roles) do
      if type(role) == "string" then
        set[role] = true
      end
    end
  end
  return set
end

-- required（設定値の配列）が present（トークン由来の集合）に全て含まれるか検査するローカル関数
-- @return 全て含まれるなら true。1 つでも欠ければ false
local function all_present(required, present)
  for _, item in ipairs(required) do
    if not present[item] then
      return false
    end
  end
  return true
end

-- 受信トークンのクレームが設定された認可要件を満たすか検証する（唯一の公開関数）
-- @param conf プラグイン設定（required_scopes / required_roles を参照）
-- @param claims 検証済み（署名・iss・aud・exp 検証を通過した）トークンのクレーム
-- @return 要件なし or 全て満たす場合は true。
--         権限不足の場合は nil, 内部ログ用の理由（レスポンスには出さない。
--         トークン由来の scp/roles の値は含めない）
function M.authorize(conf, claims)
  -- required_scopes: 設定され、かつ 1 件以上あるときだけ検査する（未設定・空配列は後方互換で素通し）
  if not is_unset(conf.required_scopes) and #conf.required_scopes > 0 then
    local scopes = parse_scp(claims.scp)
    if not all_present(conf.required_scopes, scopes) then
      -- scp 欠落（app-only 等）もここに含まれる。理由にはトークンの scp 値を載せない
      return nil, "token is missing one or more required scopes"
    end
  end

  -- required_roles: 同様に、設定され 1 件以上あるときだけ検査する
  if not is_unset(conf.required_roles) and #conf.required_roles > 0 then
    local roles = parse_roles(claims.roles)
    if not all_present(conf.required_roles, roles) then
      return nil, "token is missing one or more required roles"
    end
  end

  return true
end

return M
