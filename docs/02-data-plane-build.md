# ガイド 02: Data Plane のビルドと起動

**日本語** | [English](i18n/en/02-data-plane-build.md)

obo プラグインを組み込んだ Kong Gateway を、Konnect の Data Plane (DP) として Docker Compose で起動します。

## 前提

- Docker / Docker Compose v2
- [ガイド 01](01-custom-plugin-registration.md) の完了（CP へのスキーマ登録）
- ローカルの `8000` / `8100` / `3000` / `4317` / `4318` 番ポートが空いていること（別の Kong Gateway や他のコンテナが使用中だとポート衝突で起動に失敗します。`docker ps` 等で確認し、使用中のものは先に停止してください）

## 手順

### 1. DP 接続情報を配置する

[Gateway Manager](https://cloud.konghq.com/gateway-manager/) → 対象 Control Plane → **Data Plane Nodes** → **New Data Plane Node** で表示される接続情報から:

1. **cluster 証明書ペア**を以下に保存する（`cluster-certs/` は gitignore 済み。コミット禁止）:
   - `cluster-certs/cluster.crt`
   - `cluster-certs/cluster.key`
2. 接続先 URL のプレフィックス（`https://<PREFIX>.us.cp0.konghq.com` の `<PREFIX>` 部分）を `.env` に記入する:

   ```
   PREFIX=<DP 接続プレフィックス>
   ```

### 2. ビルドして起動する

`.env` を記入・変更した後は、必ず `.env` を読み込み直してから起動します。Docker Compose は**シェルにエクスポート済みの環境変数を `.env` より優先する**ため、[ガイド 01](01-custom-plugin-registration.md) の `source .env` 時点の古い値（空の `PREFIX`）がシェルに残っていると、`.env` に記入しても空のまま起動されてしまいます。

```bash
set -a; source .env; set +a
docker compose up --build -d
```

- `Dockerfile` が `kong/kong-gateway` ベースイメージに `luarocks make` で obo プラグインをインストールしたイメージをビルドします
- プラグインのロード（`KONG_PLUGINS=bundled,obo`）は `compose.yaml` で設定済みです

### 3. 起動を確認する

```bash
docker compose ps          # kong が healthy であること
```

[Gateway Manager](https://cloud.konghq.com/gateway-manager/) の **Data Plane Nodes** にノードが **Connected** として表示されれば完了です。

## 補足

- プラグインのコード（`kong/plugins/obo/`）を変更した場合は `docker compose up --build -d` で再ビルドしてください
- `compose.yaml` には Observability スタック（otel-lgtm）も含まれています

次: [ガイド 03: Entra ID のセットアップ](03-entra-id-setup.md)
