local plugin_name = "obo"
local package_name = "kong-plugin-" .. plugin_name
local package_version = "0.2.1"
local rockspec_revision = "1"

local github_account_name = "shukawam"
local github_repo_name = "kong-plugin-obo"
-- リリースタグ（v<version>）を参照する。リリース手順は docs/05-release.md を参照
local git_checkout = "v" .. package_version


package = package_name
version = package_version .. "-" .. rockspec_revision
supported_platforms = { "linux", "macosx" }
source = {
  url = "git+https://github.com/"..github_account_name.."/"..github_repo_name..".git",
  tag = git_checkout,
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
    ["kong.plugins."..plugin_name..".scope_validator"] = "kong/plugins/"..plugin_name.."/scope_validator.lua",
    ["kong.plugins."..plugin_name..".token_exchange"] = "kong/plugins/"..plugin_name.."/token_exchange.lua",
    ["kong.plugins."..plugin_name..".token_cache"] = "kong/plugins/"..plugin_name.."/token_cache.lua",
  }
}
