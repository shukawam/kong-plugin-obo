#!/usr/bin/env bash
# ドキュメント多言語同期チェック
#
# 日本語（マスター）が変更されたのに、対応する翻訳が追従していない状態を検知する。
# マニフェスト docs/i18n/sync-manifest.tsv に記録した「翻訳作成時点のマスターの
# git hash-object 値」と、現在のマスターのハッシュを突き合わせる。
#
# 使い方:
#   scripts/check-doc-sync.sh            # --check と同じ（CI で実行）
#   scripts/check-doc-sync.sh --check    # 追従できているか検査（ズレていれば非ゼロ終了）
#   scripts/check-doc-sync.sh --update   # 現在のマスターのハッシュで manifest を再生成
set -euo pipefail

# リポジトリのルート（このスクリプトは scripts/ 配下にある想定）
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="docs/i18n/sync-manifest.tsv"
MODE="${1:---check}"

# フィールド区切りのタブ（bash 3.2 でも動くよう printf で生成）
TAB="$(printf '\t')"

if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: マニフェストが見つかりません: $MANIFEST" >&2
  exit 1
fi

case "$MODE" in
  --check)
    fail=0
    # read の戻り値対策として `|| [ -n "$source" ]` で最終行（改行なし）も拾う
    while IFS="$TAB" read -r source lang translation recorded || [ -n "$source" ]; do
      # 空行・コメント行（# 始まり）はスキップ
      case "$source" in ''|\#*) continue ;; esac

      if [ ! -f "$source" ]; then
        echo "NG: マスター（日本語）が見つかりません: $source" >&2
        fail=1; continue
      fi
      if [ ! -f "$translation" ]; then
        echo "NG: 翻訳が見つかりません: $translation （マスター: $source, lang: $lang）" >&2
        fail=1; continue
      fi

      current="$(git hash-object "$source")"
      if [ "$current" != "$recorded" ]; then
        echo "NG: マスターが変更されています: $source" >&2
        echo "    → 翻訳 $translation を更新し、'scripts/check-doc-sync.sh --update' を実行してください" >&2
        fail=1
      fi
    done < "$MANIFEST"

    if [ "$fail" -ne 0 ]; then
      echo "" >&2
      echo "ドキュメントの多言語同期に問題があります（上記参照）。日本語をマスターとして翻訳を追従させてください。" >&2
      exit 1
    fi
    echo "OK: すべての翻訳がマスターに追従しています"
    ;;

  --update)
    # コメント行のヘッダーを固定で書き出し、データ行はハッシュを再計算して追記する
    tmp="$(mktemp)"
    {
      echo "# ドキュメント多言語同期マニフェスト"
      echo "# 列: source<TAB>lang<TAB>translation<TAB>source_hash"
      echo "# source_hash = その翻訳を作成した時点のマスター(source)の 'git hash-object' 値"
      echo "# 更新方法: 翻訳を追従させた後 'scripts/check-doc-sync.sh --update' を実行する"
    } > "$tmp"

    while IFS="$TAB" read -r source lang translation recorded || [ -n "$source" ]; do
      case "$source" in ''|\#*) continue ;; esac
      if [ ! -f "$source" ]; then
        echo "ERROR: マスターが見つかりません: $source" >&2
        rm -f "$tmp"; exit 1
      fi
      current="$(git hash-object "$source")"
      printf '%s\t%s\t%s\t%s\n' "$source" "$lang" "$translation" "$current" >> "$tmp"
    done < "$MANIFEST"

    mv "$tmp" "$MANIFEST"
    echo "OK: manifest を再生成しました: $MANIFEST"
    ;;

  *)
    echo "usage: $0 [--check|--update]" >&2
    exit 2
    ;;
esac
