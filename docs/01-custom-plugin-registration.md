# ガイド 01: Konnect へのカスタムプラグイン登録

Konnect のハイブリッドモードでは、Control Plane (CP) に obo プラグインの**スキーマ**を登録しないと、CP からプラグイン設定を Data Plane (DP) に配信できません。（DP 側へのプラグイン本体のインストールは [ガイド 02](02-data-plane-build.md) で行います）

## 前提

- Konnect アカウントと Control Plane が作成済みであること
- ツール: `mise` / `deck` / `jq` / `curl`
- Konnect のパーソナルアクセストークン（[Konnect の Personal Access Tokens ページ](https://cloud.konghq.com/global/account/tokens)で発行）

## 手順

### 1. 環境変数を設定する

```bash
cp .env.example .env
```

`.env` の以下 2 つを記入する（他の変数は後続のガイドで使用）:

```
DECK_KONNECT_TOKEN=<Konnect のパーソナルアクセストークン>
DECK_KONNECT_CONTROL_PLANE_NAME=<対象 Control Plane 名>
```

### 2. スキーマを登録する

```bash
mise run schema:upload
```

`scripts/upload-plugin-schema.sh` が Control Plane 名から ID を解決し、`kong/plugins/obo/schema.lua` を Konnect API で登録します（登録済みの場合は更新）。

### 3. 登録を確認する

```bash
mise run schema:verify
```

`OK: スキーマは登録されています` と表示されれば完了です。

## 代替手順（UI で登録する場合）

1. [Gateway Manager](https://cloud.konghq.com/gateway-manager/) で対象 Control Plane を選択
2. **Plugins** → **New Plugin** → **Custom Plugins**
3. `kong/plugins/obo/schema.lua` をアップロード

## 補足

- schema.lua を変更した場合は `mise run schema:upload` を再実行すると更新されます
- 登録後、Konnect の Plugins 一覧に `obo` が表示され、Service / Route に設定できるようになります

次: [ガイド 02: Data Plane のビルドと起動](02-data-plane-build.md)
