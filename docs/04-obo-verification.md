# ガイド 04: OBO トークン交換の確認

Kong の Route に obo プラグインを設定し、実際にユーザーのトークンをダウンストリーム API 用トークンに交換できることを確認します。

## 前提

- [ガイド 01](01-custom-plugin-registration.md)〜[03](03-entra-id-setup.md) の完了
- `.env` の全変数が記入済みであること（[ガイド 03 §5](03-entra-id-setup.md) の対応表参照）

## 手順

### 1. ゲートウェイ設定を Konnect に同期する

`examples/kong.yaml` に検証用の Service（`https://httpbin.konghq.com`）と Route（`/mock`）、obo プラグインの設定が定義されています。設定値は `.env` の `DECK_*` 変数から解決されます。

```bash
mise run gateway:diff    # 反映される差分の確認
mise run gateway:sync    # Konnect へ反映（数秒で DP に配信される）
```

`.env` の値を変更した場合は、必ず `gateway:sync` を再実行してください。

### 2. ユーザーのトークン（token A）を取得する

device code flow を使うと curl だけで取得できます。

```bash
# ① デバイスコードを取得（.env の値を読み込んで実行）
set -a; source .env; set +a
curl -s -X POST "https://login.microsoftonline.com/${DECK_TENANT_ID}/oauth2/v2.0/devicecode" \
  -d "client_id=<CLIENT_APP_ID>" \
  --data-urlencode "scope=api://${DECK_CLIENT_ID}/access_as_user"
```

レスポンスの `verification_uri` をブラウザで開き、`user_code` を入力してサインインします。

```bash
# ② サインイン完了後、トークンを取得（完了前は authorization_pending が返る）
curl -s -X POST "https://login.microsoftonline.com/${DECK_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=<CLIENT_APP_ID>" \
  -d "device_code=<①のレスポンスの device_code>"
```

レスポンスの `access_token` が token A です。

### 3. OBO 交換を確認する

```bash
TOKEN_A="<取得した access_token>"
curl -s -H "Authorization: Bearer ${TOKEN_A}" http://localhost:8000/mock/anything | jq .headers.authorization
```

httpbin の `/anything` は受信したリクエストをそのまま JSON で返すため、表示された `authorization` ヘッダーの値が **token A と異なる**（`Bearer eyJ...` の別トークン）であれば、OBO 交換が成功しています。この値が交換後トークン（token B）です。

トークンなしの場合は 401 が返ることも確認します:

```bash
curl -si http://localhost:8000/mock/anything | head -3
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer realm="kong"
```

## 確認ポイントのまとめ

| 操作 | 期待結果 |
|---|---|
| トークンなしでアクセス | `401` + `WWW-Authenticate` ヘッダー |
| token A 付きでアクセス | `200` + upstream に届く `authorization` が token B に差し替わる |

## うまくいかないとき

プラグインは失敗の詳細をレスポンスに含めず、debug ログにのみ出力します:

```bash
docker compose logs kong | grep "obo:"
```

`obo: unauthorized: <理由>` または `obo: token exchange failed: <Entra のエラー>` が表示されるので、理由に応じて [ガイド 03](03-entra-id-setup.md) の該当設定と `.env` の値（変更後は `gateway:sync`）を見直してください。
