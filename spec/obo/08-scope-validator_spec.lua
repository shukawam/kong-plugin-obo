-- 受信トークンの scp / roles による認可（Issue #1）の単体テスト
-- scope_validator は純粋な入出力（conf + claims → true / nil,err）なので kong.* のモックは不要。
-- 仕様の裏取り:
--   - scp: スペース区切りのスコープ文字列。ユーザートークンにのみ含まれる
--     （Microsoft "Access token claims reference" scp 行）。
--   - roles: 文字列の配列。app-only にもユーザーにも使われる（同 roles 行）。
--   - scp が存在しないのは daemon / app-only / id_token
--     （Microsoft "Secure applications and APIs by validating claims" > Validate the actor）。

describe("obo: scope_validator (unit)", function()
  local scope_validator

  setup(function()
    scope_validator = require("kong.plugins.obo.scope_validator")
  end)

  teardown(function()
    package.loaded["kong.plugins.obo.scope_validator"] = nil
  end)

  -- ---- 未設定（後方互換）----

  it("required_scopes / required_roles が未設定(nil)なら常に認可する", function()
    local ok, err = scope_validator.authorize({}, { scp = "access_as_user" })
    assert.is_true(ok)
    assert.is_nil(err)
  end)

  it("required_scopes / required_roles が ngx.null（省略時の正規化値）でも認可する", function()
    local conf = { required_scopes = ngx.null, required_roles = ngx.null }
    local ok = scope_validator.authorize(conf, { scp = "access_as_user" })
    assert.is_true(ok)
  end)

  it("required_scopes が空配列なら検査せず認可する（防御的挙動。空配列自体は schema で拒否される）", function()
    -- 明示的な空配列は schema の len_min = 1 で設定時に拒否されるため、
    -- 通常運用でこの分岐には到達しない。schema を経ない呼び出しに対する防御的挙動の確認
    local ok = scope_validator.authorize({ required_scopes = {} }, {})
    assert.is_true(ok)
  end)

  -- ---- required_scopes（委任スコープ）----

  it("scp に必須スコープが全て含まれれば認可する", function()
    local conf = { required_scopes = { "access_as_user", "Files.Read" } }
    local ok = scope_validator.authorize(conf, { scp = "Files.Read access_as_user Mail.Read" })
    assert.is_true(ok)
  end)

  it("scp に必須スコープの一部が欠けていれば拒否する", function()
    local conf = { required_scopes = { "access_as_user", "Files.ReadWrite" } }
    local ok, err = scope_validator.authorize(conf, { scp = "access_as_user Files.Read" })
    assert.is_nil(ok)
    assert.is_string(err)
  end)

  it("required_scopes 設定時、scp クレーム自体が無いトークン（app-only 等）を拒否する", function()
    -- scp はユーザートークンにのみ含まれる。app-only / daemon / id_token では欠落する。
    -- OBO はユーザープリンシパルのみ対象なので、必須スコープ設定時は scp 欠落を弾く
    local conf = { required_scopes = { "access_as_user" } }
    local ok, err = scope_validator.authorize(conf, { roles = { "SomeRole" } })  -- scp なし
    assert.is_nil(ok)
    assert.is_string(err)
  end)

  it("scp の余分な空白（連続スペース・前後空白）を正しく分解する", function()
    local conf = { required_scopes = { "a", "b" } }
    local ok = scope_validator.authorize(conf, { scp = "  a   b  " })
    assert.is_true(ok)
  end)

  -- ---- required_roles（アプリロール）----

  it("roles に必須ロールが全て含まれれば認可する", function()
    local conf = { required_roles = { "Task.Admin" } }
    local ok = scope_validator.authorize(conf, { roles = { "Task.Read", "Task.Admin" } })
    assert.is_true(ok)
  end)

  it("roles に必須ロールが欠けていれば拒否する", function()
    local conf = { required_roles = { "Task.Admin" } }
    local ok, err = scope_validator.authorize(conf, { roles = { "Task.Read" } })
    assert.is_nil(ok)
    assert.is_string(err)
  end)

  it("required_roles 設定時、roles クレーム自体が無いトークンを拒否する", function()
    local conf = { required_roles = { "Task.Admin" } }
    local ok, err = scope_validator.authorize(conf, { scp = "access_as_user" })  -- roles なし
    assert.is_nil(ok)
    assert.is_string(err)
  end)

  -- ---- 併用 ----

  it("required_scopes と required_roles の両方を満たせば認可する", function()
    local conf = { required_scopes = { "access_as_user" }, required_roles = { "Admin" } }
    local ok = scope_validator.authorize(conf, { scp = "access_as_user", roles = { "Admin" } })
    assert.is_true(ok)
  end)

  it("scp は満たすが roles が不足なら拒否する", function()
    local conf = { required_scopes = { "access_as_user" }, required_roles = { "Admin" } }
    local ok = scope_validator.authorize(conf, { scp = "access_as_user", roles = { "User" } })
    assert.is_nil(ok)
  end)

  it("エラー理由に受信トークンの scp / roles の値を含めない（トークン内容を漏らさない）", function()
    local conf = { required_scopes = { "needed_scope" } }
    local ok, err = scope_validator.authorize(conf, { scp = "secret_user_scope another_secret" })
    assert.is_nil(ok)
    -- 内部ログ用の理由にトークン由来の値（scp の中身）が混ざっていないこと
    assert.is_nil(err:find("secret_user_scope", 1, true))
    assert.is_nil(err:find("another_secret", 1, true))
  end)
end)
