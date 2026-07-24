# Guide 05: Release procedure

[日本語](../../05-release.md) | **English**

Create a version tag (`v<version>`) to release. The rockspec's `source` references this tag, so fetching via LuaRocks is only possible for versions that have a tag.

## Where to update the version

To bump the version, update the following three places to **exactly the same value** and commit them (a mismatch causes the release task to fail):

| Place | Example (when setting 0.2.0) |
|---|---|
| The rockspec file name | `git mv kong-plugin-obo-0.1.0-1.rockspec kong-plugin-obo-0.2.0-1.rockspec` |
| `package_version` in the rockspec | `local package_version = "0.2.0"` |
| `VERSION` in `kong/plugins/obo/handler.lua` | `VERSION = "0.2.0"` |

If you change the rockspec content itself (the source code is the same and only the build definition changes), bump `rockspec_revision` instead of the version, and update the file name suffix (`-1` → `-2`) to match.

## Running the release

```bash
mise run release
```

This task automatically does the following:

1. Confirms the working tree is clean
2. Checks consistency across the rockspec file name, `package_version`, and `VERSION` in handler.lua
3. Creates an annotated tag `v<version>` and runs `git push origin main v<version>`

When the tag is pushed, GitHub Actions (`.github/workflows/release.yml`) starts, re-verifies that the tag and version match, verifies installation via `luarocks make`, and then automatically creates a GitHub Release with release notes.

## After the release

- Confirm that `v<version>` was created on the GitHub **Releases** page
- Confirm that the tagged version can be fetched and installed with:

```bash
luarocks install https://raw.githubusercontent.com/shukawam/kong-plugin-obo/v<version>/kong-plugin-obo-<version>-1.rockspec
```
