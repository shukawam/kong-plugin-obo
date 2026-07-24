# ガイド 05: リリース手順

**日本語** | [English](i18n/en/05-release.md)

バージョンタグ（`v<version>`）を作成してリリースします。rockspec の `source` はこのタグを参照するため、LuaRocks 経由の取得はタグが存在するバージョンに対してのみ可能です。

## バージョンの更新箇所

バージョンを上げる場合は、以下の 3 箇所を**すべて同じ値**に更新してコミットします（不一致があるとリリースタスクが失敗します）:

| 箇所 | 例（0.2.0 にする場合） |
|---|---|
| rockspec のファイル名 | `git mv kong-plugin-obo-0.1.0-1.rockspec kong-plugin-obo-0.2.0-1.rockspec` |
| rockspec 内の `package_version` | `local package_version = "0.2.0"` |
| `kong/plugins/obo/handler.lua` の `VERSION` | `VERSION = "0.2.0"` |

rockspec の内容自体を変更した場合（ソースコードが同じでビルド定義のみ変更）は、バージョンではなく `rockspec_revision` を上げてファイル名の末尾（`-1` → `-2`）も合わせます。

## リリースの実行

```bash
mise run release
```

このタスクは次を自動で行います:

1. 作業ツリーがクリーンであることの確認
2. rockspec のファイル名・`package_version`・handler.lua の `VERSION` の整合性チェック
3. 注釈付きタグ `v<version>` の作成と `git push origin main v<version>`

タグが push されると GitHub Actions（`.github/workflows/release.yml`）が起動し、タグとバージョンの一致を再検証・`luarocks make` によるインストール検証を行った上で、リリースノート付きの GitHub Release を自動作成します。

## リリース後の確認

- GitHub の **Releases** ページに `v<version>` が作成されていること
- タグ済みバージョンは以下で取得・インストールできること:

```bash
luarocks install https://raw.githubusercontent.com/shukawam/kong-plugin-obo/v<version>/kong-plugin-obo-<version>-1.rockspec
```
