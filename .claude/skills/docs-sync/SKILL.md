---
name: docs-sync
description: README や docs/0X-*.md などのユーザー向けドキュメントを新規作成・編集するとき（内容の追加・修正・削除、リンク変更、ガイド追加）に必ず使う。日本語をマスターとして英語ほか全言語版を同一コミットで追従させ、同期マニフェストを更新する手順を強制する。
---

# docs-sync — ドキュメント多言語の同期

**日本語がマスター**。ユーザー向けドキュメント（`README.md`, `docs/0X-*.md`）は
必ず日本語を先に書き、対応する翻訳（`docs/i18n/<lang>/`）を**同一コミット内で**追従させる。
`docs/obo/` `docs/superpowers/` はローカル専用のため対象外。

CI（`.github/workflows/doc-sync.yml` → `scripts/check-doc-sync.sh`）が
「日本語だけ変わって翻訳が古い」状態を検知して fail させる。ローカルでも同じ
スクリプトで確認できる。

## 対応表（マニフェスト）

`docs/i18n/sync-manifest.tsv`（タブ区切り: `source ⇥ lang ⇥ translation ⇥ source_hash`）が
マスターと翻訳の対応表。`source_hash` はスクリプトが自動管理するので手で編集しない。

## 既存ドキュメントを編集するとき

1. **日本語（マスター）を編集する**。
2. マニフェストで対応する全 `translation` を探し、**同じ変更を反映**する
   （英語ほか全言語）。訳し忘れ・訳し漏れがないこと。
3. `bash scripts/check-doc-sync.sh --update` で `source_hash` を再生成する。
4. `bash scripts/check-doc-sync.sh --check` が **OK** になることを確認する。
5. マスター・翻訳・マニフェストを**1 コミットにまとめる**（テスト同様、途中状態でコミットしない）。

## 新しいドキュメントを追加するとき

1. 日本語版を `docs/` に作成する。
2. 各言語の翻訳を `docs/i18n/<lang>/` に同名で作成する。
3. `docs/i18n/sync-manifest.tsv` に言語ごとに 1 行追加する（`source_hash` は仮に `PENDING`）。
4. `--update` → `--check` を実行して緑にする。

## ドキュメント削除・リネーム時

マニフェストの該当行と、各言語の翻訳ファイルも合わせて削除・リネームする。
リネーム後は `--update` → `--check`。

## 翻訳の品質ルール

- **ガイド整形**: 段落・文の途中で改行しない（1 段落 = 1 行）。失敗談や試行過程を書かず、
  手順を実現する最小限の内容にする（CLAUDE.md の整形ルールに従う）。
- **相互リンク**: README と各言語版の先頭に言語切り替えリンクを 1 行入れる
  （例: `**English** | [日本語](../../../README.md)`）。相対パスの階層に注意する。
- **コード・コマンド・設定値・GUID・エンドポイント・クレーム名は訳さない**。UI ラベルは
  原文（日本語 UI 表記）を訳注として残すか、翻訳側の Entra UI 言語に合わせる。
- **リンク先**: マスターが同一 `docs/` 内の相対リンク（`02-...md` 等）を指す場合、翻訳側は
  同じ言語ディレクトリ内の相対リンクに張り替える（`docs/i18n/en/` 内で完結させる）。
  ルート（`../../../README.md`）や `CLAUDE.md` への相対パスは階層差に注意する。

## 用語集（英日対訳・ぶれさせない）

| 日本語 | English |
|---|---|
| オンビハーフオブ（OBO）フロー | On-Behalf-Of (OBO) flow |
| 受信トークン / token A | incoming token / token A |
| 交換後トークン / token B | exchanged token / token B |
| ミドルティア（middle-tier）アプリ | middle-tier app |
| ダウンストリーム API | downstream API |
| データプレーン (DP) / コントロールプレーン (CP) | Data Plane (DP) / Control Plane (CP) |
| 委任スコープ | delegated scope |
| アプリロール | app role |
| 事前同意 / 管理者同意 | pre-consent / admin consent |
| 認証 / 認可 | authentication / authorization |
| クライアントアサーション | client assertion |
| サムプリント | thumbprint |
| クロックスキュー | clock skew |
| 宣言的設定（DB-less） | declarative config (DB-less) |
| 権限不足 | insufficient scope |

## スクリプトの使い方

```bash
bash scripts/check-doc-sync.sh --check    # 追従できているか検査（既定・CI と同じ）
bash scripts/check-doc-sync.sh --update   # 翻訳を追従させた後にハッシュを再生成
```

`--check` が NG のときは、表示されたマスターに対応する翻訳を更新してから `--update` する。
