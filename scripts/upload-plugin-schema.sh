#!/usr/bin/env bash
# =============================================================================
# Konnect Control Plane への obo カスタムプラグインスキーマ登録スクリプト（Hybrid Mode 用）
#
# Hybrid Mode では、CP に schema.lua を登録しないとプラグイン設定を DP に配信できない。
# 参考: https://developer.konghq.com/custom-plugins/konnect-hybrid-mode/
#
# 使い方:
#   scripts/upload-plugin-schema.sh upload   # 登録（既存なら更新）
#   scripts/upload-plugin-schema.sh verify   # 登録状態の確認のみ（読み取り専用）
#
# 必要な環境変数（mise が .env から解決する。mise run schema-upload を推奨）:
#   DECK_KONNECT_TOKEN               Konnect のパーソナルアクセストークン（deck と共用）
#   DECK_KONNECT_CONTROL_PLANE_NAME  対象 Control Plane の名前（deck と共用）
# 任意:
#   KONNECT_API_URL   Konnect API のベース URL（既定: https://us.api.konghq.com）
#   PLUGIN_NAME       プラグイン名（既定: obo）
#   SCHEMA_FILE       schema.lua のパス（既定: kong/plugins/obo/schema.lua）
# =============================================================================
set -euo pipefail

# --- 設定（環境変数で上書き可能） ---
KONNECT_API_URL="${KONNECT_API_URL:-https://us.api.konghq.com}"
PLUGIN_NAME="${PLUGIN_NAME:-obo}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA_FILE="${SCHEMA_FILE:-${REPO_ROOT}/kong/plugins/${PLUGIN_NAME}/schema.lua}"

MODE="${1:-upload}"

# --- 前提チェック ---
for cmd in curl jq; do
  command -v "$cmd" >/dev/null || { echo "ERROR: $cmd が見つかりません" >&2; exit 1; }
done
: "${DECK_KONNECT_TOKEN:?ERROR: DECK_KONNECT_TOKEN が未設定です（.env を確認。mise run 経由で実行すること）}"
: "${DECK_KONNECT_CONTROL_PLANE_NAME:?ERROR: DECK_KONNECT_CONTROL_PLANE_NAME が未設定です（.env を確認）}"
[ -f "$SCHEMA_FILE" ] || { echo "ERROR: schema ファイルがありません: $SCHEMA_FILE" >&2; exit 1; }

# Konnect API を呼ぶ共通関数。トークンはログに出さない
konnect_api() {
  local method="$1" path="$2"; shift 2
  curl --silent --show-error --fail-with-body \
    -X "$method" \
    -H "Authorization: Bearer ${DECK_KONNECT_TOKEN}" \
    -H "Content-Type: application/json" \
    "$@" \
    "${KONNECT_API_URL}${path}"
}

# --- ① Control Plane 名から ID を解決する ---
echo "==> Control Plane '${DECK_KONNECT_CONTROL_PLANE_NAME}' の ID を解決中..."
CP_RESPONSE=$(curl --silent --show-error --fail-with-body -G \
  -H "Authorization: Bearer ${DECK_KONNECT_TOKEN}" \
  --data-urlencode "filter[name][eq]=${DECK_KONNECT_CONTROL_PLANE_NAME}" \
  "${KONNECT_API_URL}/v2/control-planes") || {
    echo "ERROR: Control Plane 一覧の取得に失敗（トークンや KONNECT_API_URL のリージョンを確認）" >&2; exit 1; }

CONTROL_PLANE_ID=$(echo "$CP_RESPONSE" | jq -r '.data[0].id // empty')
[ -n "$CONTROL_PLANE_ID" ] || {
  echo "ERROR: Control Plane '${DECK_KONNECT_CONTROL_PLANE_NAME}' が見つかりません" >&2; exit 1; }
echo "    Control Plane ID: ${CONTROL_PLANE_ID}"

SCHEMAS_PATH="/v2/control-planes/${CONTROL_PLANE_ID}/core-entities/plugin-schemas"

# --- ② 登録済みかを確認する ---
echo "==> プラグインスキーマ '${PLUGIN_NAME}' の登録状態を確認中..."
if EXISTING=$(konnect_api GET "${SCHEMAS_PATH}/${PLUGIN_NAME}" 2>/dev/null); then
  REGISTERED=true
  echo "    登録済み（作成日時: $(echo "$EXISTING" | jq -r '.item.created_at // "不明"')）"
else
  REGISTERED=false
  echo "    未登録"
fi

if [ "$MODE" = "verify" ]; then
  # verify モードはここで終了（読み取り専用）
  [ "$REGISTERED" = true ] && echo "OK: スキーマは登録されています" || {
    echo "NG: スキーマが未登録です。'mise run schema-upload' で登録してください"; exit 1; }
  exit 0
fi

# --- ③ 登録（未登録なら POST、登録済みなら PATCH で更新） ---
# schema.lua の中身を JSON 文字列にエンコードしてボディを作る
BODY=$(jq -n --rawfile schema "$SCHEMA_FILE" '{"lua_schema": $schema}')

if [ "$REGISTERED" = true ]; then
  echo "==> 既存スキーマを更新中 (PATCH)..."
  konnect_api PATCH "${SCHEMAS_PATH}/${PLUGIN_NAME}" --data "$BODY" >/dev/null
  echo "    更新しました"
else
  echo "==> スキーマを新規登録中 (POST)..."
  konnect_api POST "$SCHEMAS_PATH" --data "$BODY" >/dev/null
  echo "    登録しました"
fi

# --- ④ 登録結果を検証する ---
echo "==> 登録結果を検証中..."
konnect_api GET "${SCHEMAS_PATH}/${PLUGIN_NAME}" | jq '{name: .item.name, created_at: .item.created_at, updated_at: .item.updated_at}'
echo "完了: Konnect 側でプラグイン '${PLUGIN_NAME}' を Service/Route に設定できるようになりました"
