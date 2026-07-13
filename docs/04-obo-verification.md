# ガイド 04: OBO トークン交換の確認

Kong の Route に obo プラグインを設定し、実際にユーザーのトークンをダウンストリーム API 用トークンに交換できることを確認します。

## 前提

- [ガイド 01](01-custom-plugin-registration.md)〜[03](03-entra-id-setup.md) の完了
- `.env` の全変数が記入済みであること（[ガイド 03 §5](03-entra-id-setup.md) の対応表参照）
- `.env` の `DECK_DOWNSTREAM_URL` に、token B の実際の audience である downstream API のベース URL を設定していること（例: Microsoft Graph なら `https://graph.microsoft.com`、[ガイド 03](03-entra-id-setup.md) で登録した自前のテスト API ならそのベース URL）

## 手順

### 1. ゲートウェイ設定を Konnect に同期する

`examples/kong.yaml` に検証用の Service（upstream は `.env` の `DECK_DOWNSTREAM_URL`、すなわち token B の正規 audience である downstream API）と Route（`/downstream`）、obo プラグインの設定が定義されています。設定値は `.env` の `DECK_*` 変数から解決されます。

同期の前に、`DECK_DOWNSTREAM_URL` が `https://` で始まることを確認します。token B が平文で送信されるのを防ぐため HTTPS は必須です。また、この URL は `DECK_SCOPE` の audience（token B の正規の届け先）と一致している必要があります。

```bash
set -a; source .env; set +a
[[ "$DECK_DOWNSTREAM_URL" == https://* ]] && echo OK || echo "NG: DECK_DOWNSTREAM_URL は https:// で始まる必要があります"
# OK
```

```bash
mise run gateway:diff    # 反映される差分の確認
mise run gateway:sync    # Konnect へ反映（数秒で DP に配信される）
```

`.env` の値を変更した場合は、必ず `gateway:sync` を再実行してください。

### 2. 配線確認（モックトークンのみ使用）

`/downstream` にトークンなし、および実トークンではないダミー文字列でアクセスし、obo プラグインが 401 を返すことを確認します。いずれもプラグインが upstream への到達前にリクエストを拒否するため、downstream API にリクエストは送信されません。401 が返ること自体が「Route にプラグインが効いている」ことの確認になります。

```bash
curl -si http://localhost:8000/downstream | head -3
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer realm="kong"
```

```bash
curl -si -H "Authorization: Bearer this-is-a-mock-token" http://localhost:8000/downstream | head -3
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer error="invalid_token"
```

### 3. ユーザーのトークン（token A）を取得する

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

### 4. 実トークンで OBO 交換を確認する

`/downstream` に token A 付きでアクセスし、HTTP ステータスコードだけを確認します（token B の値は表示しません）。200 が返れば、Kong が token A を検証し、Entra ID から token B を取得して downstream API への転送に成功したことを意味します。

```bash
TOKEN_A="<取得した access_token>"
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  "http://localhost:8000/downstream/<downstream API 上のパス>"
# 200
```

Microsoft Graph を downstream API にする場合、`<downstream API 上のパス>` は `v1.0/me`、`.env` の `DECK_SCOPE` は `https://graph.microsoft.com/user.read` にしてください。あわせて、middle-tier アプリの **API permissions** に Microsoft Graph の委任アクセス許可 `User.Read` を追加し、管理者の同意（**Grant admin consent**）を与えておく必要があります。

## 確認ポイントのまとめ

| 操作 | 期待結果 |
|---|---|
| `/downstream` にトークンなしでアクセス | `401` + `WWW-Authenticate` ヘッダー（upstream には到達しない） |
| `/downstream` にダミー文字列でアクセス | `401` + `WWW-Authenticate: Bearer error="invalid_token"`（upstream には到達しない） |
| `/downstream` に token A 付きでアクセス | `200`（token B への交換と downstream API への到達が成功） |

## うまくいかないとき

プラグインは失敗の詳細をレスポンスに含めず、debug ログにのみ出力します:

```bash
docker compose logs kong | grep "obo:"
```

`obo: unauthorized: <理由>` または `obo: token exchange failed: <Entra のエラー>` が表示されるので、理由に応じて [ガイド 03](03-entra-id-setup.md) の該当設定と `.env` の値（変更後は `gateway:sync`）を見直してください。

Microsoft Graph を downstream API にした構成でトークン交換が失敗する場合は、middle-tier アプリに Microsoft Graph の委任アクセス許可 `User.Read` と管理者の同意が付与されているか（§4 参照）も確認してください。
