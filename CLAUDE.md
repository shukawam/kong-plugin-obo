# kong-plugin-obo

Microsoft Entra ID の On-Behalf-Of (OBO) フローを実現する Kong Gateway カスタムプラグイン。
クライアントから受信したユーザーのアクセストークンを検証し、Entra ID でダウンストリーム API 用の
トークンに交換して、upstream への `Authorization` ヘッダーを差し替える。

## 最重要ルール

1. **プロトコルの詳細は必ず `docs/obo/` を参照する。** 記憶や推測で Entra ID / OAuth の
   仕様（パラメータ名・URN・クレーム・エンドポイント）を書かないこと。`docs/obo/` は
   一次情報（Microsoft Learn / IETF RFC）の裏取り済み仕様書である。
2. **TDD を厳守する。** 実装コードを書く前に必ず失敗するテストを書く
   （Red → Green → Refactor）。superpowers:test-driven-development スキルに従うこと。
3. **認証プラグインである。** トークン・シークレット・アサーションを絶対にログに出力しない。
   エラーレスポンスに内部の失敗理由の詳細を含めない（debug ログのみ）。
4. **コメントは日本語で丁寧に書く。** Lua 初学者でも読めるように、各関数の目的・引数・戻り値、
   非自明な処理の理由をコメントする。Lua 特有のイディオム（`local` の意味、`pcall`、
   メタテーブル等）を使う箇所には一言説明を添える。
5. **`docs/` はローカル専用**（.gitignore 済み）。コミットしないこと。

## ドキュメントの場所

| パス | 内容 | Git 管理 |
|---|---|---|
| `docs/obo/` | Entra ID OBO 仕様書（一次情報の裏取り済み） | ローカルのみ |
| `docs/superpowers/specs/2026-07-10-obo-plugin-design.md` | 承認済み設計書 | ローカルのみ |
| `docs/plans/` | 実装計画 | ローカルのみ |

## アーキテクチャ

プラグイン名は `obo`。`handler.lua` はオーケストレーションに徹し、ロジックは責務別モジュールに分割する。

```
kong/plugins/obo/
├── handler.lua           -- access フェーズのオーケストレーションのみ
├── schema.lua            -- 設定スキーマ（条件付き必須チェック含む）
├── jwt_validator.lua     -- 受信 JWT の検証（JWKS 取得・署名・クレーム）→ docs/obo/05
├── client_assertion.lua  -- private_key_jwt 用アサーション生成（PS256 + x5t#S256）→ docs/obo/04
├── token_exchange.lua    -- Entra ID への OBO リクエスト → docs/obo/02, 03
└── token_cache.lua       -- 交換済みトークンの kong.cache キャッシュ
```

- 依存は Kong 同梱の `lua-resty-http` と `lua-resty-openssl` のみ。外部依存を追加しない。
- 各モジュールは `kong.*` のモックだけで busted 単体テストできる純粋な入出力を持たせる。
- 新しい Lua ファイルを追加したら **rockspec の `build.modules` に必ず追記する**。

## テスト（二層構造）

- 単体テスト: `spec/obo/0X-*_spec.lua` — モジュールごと。`kong.*` / `resty.http` はモック。
  高速に回るので TDD のループはこちらで回す。
- 統合テスト: `spec/obo/10-integration_spec.lua` — pongo 上でモック Entra ID フィクスチャを
  使った end-to-end。
- テスト用 RSA 鍵・署名済みテスト JWT は `spec/fixtures/` に固定コミットする。
- テストの書き方のパターンは `kong-plugin-test-patterns` スキルを参照。

## コマンド

テスト実行の詳細・トラブルシュートは `pongo-testing` スキルを参照。

```bash
pongo up                          # 依存コンテナ（Postgres）起動
pongo run                         # 全テスト実行
pongo run spec/obo/04-jwt-validator_spec.lua   # 単一 spec 実行（TDD ループはこれ）
pongo lint                        # luacheck 実行
pongo down                        # コンテナ停止
```

- Lua ファイルを編集すると PostToolUse フックが自動で `luacheck` を実行する（ローカルに
  luacheck がある場合）。フックがエラーを返したら必ず修正してから先に進むこと。

## コーディング規約

- `.editorconfig` / `.luacheckrc` に従う（インデント 2 スペース、`std = ngx_lua`）。
- モジュールは `local M = {}` ... `return M` 形式。グローバルを作らない。
- エラーは `nil, err` の 2 値返し（Kong / OpenResty の慣習）。`error()` で例外を投げない。
- 時刻は `ngx.time()`、ログは `kong.log.*` を使う（`os.time()` / `print` は使わない）。
- HTTP レスポンスの終了は `kong.response.exit(status, body, headers)` を使う。

## Git 規約

- コミットメッセージは Conventional Commits（`feat:` / `fix:` / `test:` / `docs:` / `chore:`）。
- 実装ステップごとに「テスト + 実装」を 1 コミットにまとめる。テストが通らない状態でコミットしない。
