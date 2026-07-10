---
name: pongo-testing
description: Kong プラグインのテストを kong-pongo で実行する方法。テストの実行・lint・シェル操作・トラブルシューティング。テストを実行する前、またはテストが失敗して原因が環境にありそうなときに使う。
---

# pongo によるテスト実行

[kong-pongo](https://github.com/Kong/kong-pongo) は Kong プラグイン用のテスト環境。
Docker 上に Kong + Postgres を立て、その中で busted テストを実行する。

## 前提

- Docker が起動していること（`docker info` で確認）
- `pongo` コマンドが PATH にあること（`pongo --version` で確認）
- このリポジトリの設定: `.pongo/pongorc` に `--postgres --no-cassandra`

## 基本コマンド

```bash
pongo up                # 依存コンテナ（Postgres）を起動（初回・pongo down 後に必要）
pongo build             # テストイメージをビルド（Kong バージョン変更時・初回）
pongo run               # spec/ 以下の全テストを実行
pongo run spec/obo/01-schema_spec.lua       # 単一 spec ファイルだけ実行
pongo run -- --filter "キーワード"           # テスト名でフィルタ（-- 以降は busted の引数）
pongo lint              # luacheck をコンテナ内で実行
pongo shell             # コンテナ内シェル（kong start 等で手動確認できる）
pongo down              # コンテナ停止・破棄
```

- `--` 以降の引数はそのまま busted に渡る。`--filter` / `--exclude-tags` などが使える。
- Kong バージョンを変えたいとき: `KONG_VERSION=3.9.x pongo run`（既定は stable）。

## TDD ループの回し方

1. 失敗するテストを書く
2. `pongo run spec/obo/<対象>_spec.lua` — **単一ファイル指定で回す**（全実行より圧倒的に速い）
3. 最小の実装でテストを通す
4. リファクタリングして再実行
5. ステップ完了時に `pongo run`（全件）+ `pongo lint` で確認

単体テスト（モジュール直接 require + モック）は Kong を起動しないので数秒で終わる。
統合テスト（`helpers.start_kong` を使うもの）は Kong の起動を伴うため数十秒かかる。
TDD のループは単体テストで回し、統合テストはステップの締めで実行する。

## トラブルシューティング

| 症状 | 対処 |
|---|---|
| `Cannot connect to the Docker daemon` | Docker Desktop を起動する |
| `pongo: command not found` | kong-pongo をインストールして PATH を通す（README 参照） |
| DB 接続エラー / postgres unhealthy | `pongo down && pongo up` で作り直す |
| イメージ関連の不可解なエラー | `pongo build --force` で再ビルド。それでもだめなら `pongo clean` |
| テスト間で状態が残る | `servroot` ディレクトリを削除（gitignore 済み）。`helpers.stop_kong(nil, true)` の第2引数で DB クリーンを確認 |
| プラグインがロードされない | 統合テストの `plugins = "bundled,obo"` 設定と、rockspec の `build.modules` への追記漏れを確認 |
| `module 'kong.plugins.obo.xxx' not found` | rockspec の `build.modules` に新モジュールを追記後、`pongo run` は自動で再インストールする。だめなら `pongo build` |

## 注意

- テストは必ず pongo コンテナ内で実行する。ホストの busted で `spec/helpers` は動かない。
- CI（GitHub Actions）も同じ pongo を使う（`.github/workflows/test.yml`）。
  ローカルで `pongo run` が通れば CI も基本的に通る。
