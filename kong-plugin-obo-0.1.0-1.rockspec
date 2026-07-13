local plugin_name = "obo"
local package_name = "kong-plugin-" .. plugin_name
local package_version = "0.1.0"
local rockspec_revision = "1"

local github_account_name = "shukawam"
local github_repo_name = "kong-plugin-obo"
-- リリースタグ運用を始めるまでは main ブランチを参照する。
-- リリース時は source を tag = package_version（例: "0.1.0"）へ切り替えること
local git_checkout = "main"


package = package_name
version = package_version .. "-" .. rockspec_revision
supported_platforms = { "linux", "macosx" }
source = {
  url = "git+https://github.com/"..github_account_name.."/"..github_repo_name..".git",
  branch = git_checkout,
}


description = {
  summary = "Kong plugin implementing the Microsoft Entra ID On-Behalf-Of (OBO) flow",
  homepage = "https://"..github_account_name..".github.io/"..github_repo_name,
  license = "Apache 2.0",
}


dependencies = {
}


build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..plugin_name..".handler"] = "kong/plugins/"..plugin_name.."/handler.lua",
    ["kong.plugins."..plugin_name..".schema"] = "kong/plugins/"..plugin_name.."/schema.lua",
    ["kong.plugins."..plugin_name..".util"] = "kong/plugins/"..plugin_name.."/util.lua",
    ["kong.plugins."..plugin_name..".client_assertion"] = "kong/plugins/"..plugin_name.."/client_assertion.lua",
    ["kong.plugins."..plugin_name..".jwt_validator"] = "kong/plugins/"..plugin_name.."/jwt_validator.lua",
    ["kong.plugins."..plugin_name..".token_exchange"] = "kong/plugins/"..plugin_name.."/token_exchange.lua",
    ["kong.plugins."..plugin_name..".token_cache"] = "kong/plugins/"..plugin_name.."/token_cache.lua",
  }
}
