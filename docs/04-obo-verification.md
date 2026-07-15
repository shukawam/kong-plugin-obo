# ガイド 04: OBO トークン交換の確認

Kong の Route に obo プラグインを設定し、実際にユーザーのトークンをダウンストリーム API 用トークンに交換できることを確認します。

## 前提

- [ガイド 01](01-custom-plugin-registration.md)〜[03](03-entra-id-setup.md) の完了
- ツール: `curl` / `jq` / `deck`（token B のデコードに [jwt-cli](https://github.com/mike-engel/jwt-cli) の `jwt` コマンドがあると便利）
- `.env` の全変数が記入済みであること（[ガイド 03 §5](03-entra-id-setup.md) の対応表参照）
- `.env` の `DECK_DOWNSTREAM_URL` に、token B の実際の audience である downstream API のベース URL を設定していること。[ガイド 03](03-entra-id-setup.md) で登録した downstream API が実サービスを持たないテスト用アプリの場合は、リクエストエコー API `https://httpbin.org` を設定してください（§4〜5 で token B の内容まで確認できます）。Microsoft Graph を downstream にする場合は `https://graph.microsoft.com` を設定します（「補足」参照）

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
deck gateway diff examples/kong.yaml    # 反映される差分の確認
deck gateway sync examples/kong.yaml    # Konnect へ反映（数秒で DP に配信される）
```

deck は上で読み込んだ `DECK_*` 環境変数を参照するため、`.env` を読み込んだ同じシェルで実行してください。[mise](https://mise.jdx.dev/) を使っている場合は `mise run gateway:diff` / `mise run gateway:sync` でも実行できます（mise が `.env` を自動で読み込むため `source` は不要）。

`.env` の値を変更した場合は、必ず `deck gateway sync` を再実行してください。

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
# ① デバイスコードを取得し、サインイン手順を表示する
set -a; source .env; set +a
DEVICE_RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/${DECK_TENANT_ID}/oauth2/v2.0/devicecode" \
  -d "client_id=${CLIENT_APP_ID}" \
  --data-urlencode "scope=api://${DECK_CLIENT_ID}/access_as_user")
echo "$DEVICE_RESPONSE" | jq -r .message
```

表示された URL（`verification_uri`）をブラウザで開き、コード（`user_code`）を入力してサインインします。

```bash
# ② サインイン完了後、トークン（token A）を取得する
TOKEN_A=$(curl -s -X POST "https://login.microsoftonline.com/${DECK_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=$(echo "$DEVICE_RESPONSE" | jq -r .device_code)" \
  -d "client_id=${CLIENT_APP_ID}" | jq -r .access_token)
[ "$TOKEN_A" != "null" ] && echo "OK: token A を取得しました"
# OK: token A を取得しました
```

サインイン完了前に②を実行すると `authorization_pending` エラーで `TOKEN_A` が `null` になります。その場合はサインイン完了後に②だけ再実行してください。

### 4. 実トークンで OBO 交換を確認する

`/downstream` に token A 付きでアクセスします。`DECK_DOWNSTREAM_URL` が `https://httpbin.org` の場合、`/anything` エンドポイントが受信したリクエストをそのまま JSON で返すため、upstream に届いた `Authorization` ヘッダー（＝Kong が差し替えた token B）を取り出して確認できます。

```bash
TOKEN_B=$(curl -s -H "Authorization: Bearer ${TOKEN_A}" \
  "http://localhost:8000/downstream/anything" | jq -r '.headers.Authorization' | sed 's/^Bearer //')
[ "$TOKEN_B" != "null" ] && [ "$TOKEN_B" != "$TOKEN_A" ] && echo "OK: Authorization が token B に差し替わっています"
# OK: Authorization が token B に差し替わっています
```

> **注意**: この確認では token B（実トークン）が `DECK_DOWNSTREAM_URL` のサービス（httpbin.org の場合は第三者のサービス）に送信されます。token B の audience が実サービスを持たないテスト用アプリである場合に限って使用し、Microsoft Graph 等の実在 API のトークンでは行わないでください。

### 5. token B の中身を検証する

[jwt-cli](https://github.com/mike-engel/jwt-cli) の `jwt` コマンドでデコードし、交換後トークンのクレームを確認します。

```bash
jwt decode "$TOKEN_B"
```

確認する項目:

- `aud` が downstream API（`api://<DOWNSTREAM_ID>`。アプリの構成によっては素の GUID）になっていること（token A の `aud` は middle-tier なので、交換で差し替わったことが分かる）
- `scp` に `Data.Read`（`DECK_SCOPE` で要求したスコープ名）が含まれていること

`jwt` コマンドがない場合は、[jwt.io](https://jwt.io/) のデコーダーに token B を貼り付けても確認できます（macOS では `printf %s "$TOKEN_B" | pbcopy` でコピー）。デコードはブラウザ内で完結しますが、貼り付けるのはテスト用アプリ宛ての token B に限ってください。

## 確認ポイントのまとめ

| 操作 | 期待結果 |
|---|---|
| `/downstream` にトークンなしでアクセス | `401` + `WWW-Authenticate` ヘッダー（upstream には到達しない） |
| `/downstream` にダミー文字列でアクセス | `401` + `WWW-Authenticate: Bearer error="invalid_token"`（upstream には到達しない） |
| `/downstream/anything` に token A 付きでアクセス | エコーされた `Authorization` ヘッダーが token A と異なる token B になっている |
| token B をデコード | `aud` が downstream API、`scp` に `Data.Read` が含まれる |

## 補足: Microsoft Graph を downstream API にする場合

`.env` は `DECK_DOWNSTREAM_URL=https://graph.microsoft.com`、`DECK_SCOPE=https://graph.microsoft.com/user.read` にします。あわせて、middle-tier アプリの **API のアクセス許可** に Microsoft Graph の委任アクセス許可 `User.Read` を追加し、管理者の同意（**<テナント名> に管理者の同意を付与する**）を与えておく必要があります。Graph にはエコー用のエンドポイントがないため、§4〜5 の代わりにプロフィール取得の成功（`200`）で確認します（token B の中身の検証は行いません）。

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  "http://localhost:8000/downstream/v1.0/me"
# 200
```

## うまくいかないとき

プラグインは失敗の詳細をレスポンスに含めず、debug ログにのみ出力します:

```bash
docker compose logs kong | grep "obo:"
```

`obo: unauthorized: <理由>` または `obo: token exchange failed: <Entra のエラー>` が表示されるので、理由に応じて [ガイド 03](03-entra-id-setup.md) の該当設定と `.env` の値（変更後は `deck gateway sync`）を見直してください。

Microsoft Graph を downstream API にした構成でトークン交換が失敗する場合は、middle-tier アプリに Microsoft Graph の委任アクセス許可 `User.Read` と管理者の同意が付与されているか（「補足」参照）も確認してください。
