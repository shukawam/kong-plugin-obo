# ガイド 02: Data Plane のビルドと起動

obo プラグインを組み込んだ Kong Gateway を、Konnect の Data Plane (DP) として
Docker Compose で起動します。

## 前提

- Docker / Docker Compose v2
- [ガイド 01](01-custom-plugin-registration.md) の完了（CP へのスキーマ登録）

## 手順

### 1. DP 接続情報を配置する

[Gateway Manager](https://cloud.konghq.com/gateway-manager/) → 対象 Control Plane →
**Data Plane Nodes** → **New Data Plane Node** で表示される接続情報から:

1. **cluster 証明書ペア**を以下に保存する（`cluster-certs/` は gitignore 済み。コミット禁止）:
   - `cluster-certs/cluster.crt`
   - `cluster-certs/cluster.key`
2. 接続先 URL のプレフィックス（`https://<PREFIX>.us.cp0.konghq.com` の `<PREFIX>` 部分）を
   `.env` に記入する:

   ```
   PREFIX=<DP 接続プレフィックス>
   ```

### 2. ビルドして起動する

```bash
docker compose up --build -d
```

- `Dockerfile` が `kong/kong-gateway` ベースイメージに `luarocks make` で
  obo プラグインをインストールしたイメージをビルドします
- プラグインのロード（`KONG_PLUGINS=bundled,obo`）は `compose.yaml` で設定済みです

### 3. 起動を確認する

```bash
docker compose ps          # kong が healthy であること
```

[Gateway Manager](https://cloud.konghq.com/gateway-manager/) の **Data Plane Nodes** に
ノードが **Connected** として表示されれば完了です。

## 補足

- プラグインのコード（`kong/plugins/obo/`）を変更した場合は
  `docker compose up --build -d` で再ビルドしてください
- `compose.yaml` には Observability スタック（otel-lgtm）も含まれています

次: [ガイド 03: Entra ID のセットアップ](03-entra-id-setup.md)
