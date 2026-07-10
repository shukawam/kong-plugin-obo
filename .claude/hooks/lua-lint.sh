#!/usr/bin/env bash
# PostToolUse フック: Edit/Write で .lua ファイルが変更されたら luacheck を自動実行する。
# luacheck がエラー/警告を返した場合は exit 2 で Claude にフィードバックし、修正を促す。
# ローカルに luacheck がない場合は何もしない（pongo lint で代替できるため）。
set -u

# フックの入力は stdin に JSON で渡される（tool_input.file_path に対象ファイルパス）
INPUT=$(cat)

FILE=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get("tool_input", {}).get("file_path", ""))
except Exception:
    pass
' 2>/dev/null)

# 対象が .lua ファイルでなければ何もしない
[ -z "$FILE" ] && exit 0
case "$FILE" in
  *.lua) ;;
  *) exit 0 ;;
esac
[ -f "$FILE" ] || exit 0

# luacheck が入っていなければスキップ（CI と pongo lint が最終防衛線）
command -v luacheck >/dev/null 2>&1 || exit 0

OUTPUT=$(luacheck --codes "$FILE" 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
  # exit 2 にすると stderr の内容が Claude へのフィードバックとして表示される
  {
    echo "luacheck が ${FILE} で問題を検出しました。先に進む前に修正してください:"
    echo "$OUTPUT"
  } >&2
  exit 2
fi

exit 0
