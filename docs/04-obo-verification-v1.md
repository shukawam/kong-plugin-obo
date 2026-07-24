# ガイド 04-v1: OBO トークン交換の確認（v1.0 トークン）

**日本語** | [English](i18n/en/04-obo-verification-v1.md)

クライアントから **v1.0 形式のアクセストークン**（`ver: "1.0"`、`iss: https://sts.windows.net/{tid}/`）が届く環境を再現し、`allow_v1_tokens: true` を設定した obo プラグインが検証とトークン交換を行えることを確認します。

標準構成（v2.0 トークン）の検証は [ガイド 04: OBO トークン交換の確認（v2.0 トークン・標準構成）](04-obo-verification-v2.md) を使ってください。v1.0 トークンの受理はアプリ登録のマニフェストを変更できない環境向けの構成であり、可能であれば `requestedAccessTokenVersion: 2`（v2.0 への移行）を優先することを推奨します（[ガイド 03 §3.2](03-entra-id-setup.md)）。

## 前提

- [ガイド 01](01-custom-plugin-registration.md)〜[03](03-entra-id-setup.md) の完了（このガイドの §1〜2 でガイド 03 の設定の一部を v1.0 用に変更します）
- ツール: `curl` / `jq` / `deck` / [jwt-cli](https://github.com/mike-engel/jwt-cli) の `jwt` コマンド（このガイドではトークンのバージョン確認に使うため必須扱いです）
- `.env` の全変数が記入済みであること（[ガイド 03 §5](03-entra-id-setup.md) の対応表参照）
- `.env` の `DECK_DOWNSTREAM_URL` に、token B の実際の audience である downstream API のベース URL を設定していること。[ガイド 03](03-entra-id-setup.md) で登録した downstream API が実サービスを持たないテスト用アプリの場合は、リクエストエコー API `https://httpbin.org` を設定してください（§6〜7 で token B の内容まで確認できます）

## 手順

### 1. middle-tier アプリが v1.0 トークンを発行する状態にする

トークンのバージョンは、クライアントのライブラリや使用するエンドポイントではなく、**受信側（middle-tier）アプリ登録のマニフェストの `api.requestedAccessTokenVersion`** だけで決まります（`null` または `1` → v1.0、`2` → v2.0）。

1. Entra 管理センターで **middle-tier アプリ**の **マニフェスト** ページを開く
2. `api.requestedAccessTokenVersion` を `null`（既定値）または `1` にして **保存**（[ガイド 03 §3.2](03-entra-id-setup.md) で `2` を設定済みの場合は戻す）

```json
"api": {
    "requestedAccessTokenVersion": null
}
```

> **注意**: この設定は**変更後に新しく発行されたトークン**から効きます。変更前に取得したトークン（MSAL 等のクライアントは既定で 60〜90 分キャッシュします）は元のバージョンのままなので、§4 では必ず新規にトークンを取得してください。

### 2. プラグインを v1.0 トークン受理の構成にする

v1.0 トークンの `aud` クレームは素の GUID ではなく **App ID URI 形式**（`api://<MIDDLE_TIER_ID>`）になります。`.env` の `DECK_AUDIENCE` を v1.0 用の値に変更します。

```bash
# .env（ガイド 03 §5 の表では v2.0 用に素の GUID を設定している）
DECK_AUDIENCE=api://<MIDDLE_TIER_ID>
```

`examples/kong.yaml` の obo プラグイン設定でコメントアウトされている `allow_v1_tokens: true` を有効化します。

```yaml
          audiences:
            - ${{ env "DECK_AUDIENCE" }}
          allow_v1_tokens: true
```

変更をゲートウェイに反映します（`deck` は `DECK_*` 環境変数を参照するため、`.env` を読み込んだ同じシェルで実行してください）。

```bash
set -a; source .env; set +a
deck gateway diff examples/kong.yaml    # audiences と allow_v1_tokens の差分が出ることを確認
deck gateway sync examples/kong.yaml    # Konnect へ反映（数秒で DP に配信される）
```

### 3. 配線確認（モックトークンのみ使用）

`/downstream` にトークンなし、および実トークンではないダミー文字列でアクセスし、obo プラグインが 401 を返すことを確認します。いずれもプラグインが upstream への到達前にリクエストを拒否するため、downstream API にリクエストは送信されません。

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

### 4. ユーザーのトークン（token A）を取得する

device code flow を使うと curl だけで取得できます。トークンリクエストは v2.0 エンドポイント（`/oauth2/v2.0/...`）のままで問題ありません（発行されるトークンのバージョンは §1 のマニフェスト設定だけで決まり、エンドポイントには依存しません）。

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

### 5. token A が v1.0 形式であることを確認する

このガイドの検証は「届いたトークンが本当に v1.0 形式であること」が前提なので、交換を試す前にデコードして確認します（token A は自分たちのアプリ宛てのトークンなので、ローカルでのデコードは問題ありません。外部サイトには貼り付けないでください）。

```bash
jwt decode "$TOKEN_A"
```

確認する項目:

- `ver` が `"1.0"` であること（`"2.0"` の場合は §1 のマニフェスト変更が効いていません。保存済みかを確認し、**新しいトークンを取得し直して**ください）
- `iss` が `https://sts.windows.net/<TENANT_ID>/`（末尾スラッシュ付き）であること
- `aud` が `api://<MIDDLE_TIER_ID>`（§2 で `DECK_AUDIENCE` に設定した値と完全一致）であること
- `scp` に `access_as_user` が含まれること

### 6. 実トークンで OBO 交換を確認する

`/downstream` に token A 付きでアクセスします。`DECK_DOWNSTREAM_URL` が `https://httpbin.org` の場合、`/anything` エンドポイントが受信したリクエストをそのまま JSON で返すため、upstream に届いた `Authorization` ヘッダー（＝Kong が差し替えた token B）を取り出して確認できます。

```bash
TOKEN_B=$(curl -s -H "Authorization: Bearer ${TOKEN_A}" \
  "http://localhost:8000/downstream/anything" | jq -r '.headers.Authorization' | sed 's/^Bearer //')
[ "$TOKEN_B" != "null" ] && [ "$TOKEN_B" != "$TOKEN_A" ] && echo "OK: Authorization が token B に差し替わっています"
# OK: Authorization が token B に差し替わっています
```

> **注意**: この確認では token B（実トークン）が `DECK_DOWNSTREAM_URL` のサービス（httpbin.org の場合は第三者のサービス）に送信されます。token B の audience が実サービスを持たないテスト用アプリである場合に限って使用し、Microsoft Graph 等の実在 API のトークンでは行わないでください。

### 7. token B の中身を検証する

```bash
jwt decode "$TOKEN_B"
```

確認する項目:

- `aud` が downstream API（`api://<DOWNSTREAM_ID>`。アプリの構成によっては素の GUID）になっていること（token A の `aud` は middle-tier なので、交換で差し替わったことが分かる）
- `scp` に `Data.Read`（`DECK_SCOPE` で要求したスコープ名）が含まれていること

> **補足**: token B の形式（v1.0 / v2.0）は **downstream API 側**の `requestedAccessTokenVersion` で決まります。受信した token A が v1.0 でも OBO 交換自体は成功し、token B のバージョンとは無関係です。

## 確認ポイントのまとめ

| 操作 | 期待結果 |
|---|---|
| `/downstream` にトークンなしでアクセス | `401` + `WWW-Authenticate` ヘッダー（upstream には到達しない） |
| `/downstream` にダミー文字列でアクセス | `401` + `WWW-Authenticate: Bearer error="invalid_token"`（upstream には到達しない） |
| token A をデコード | `ver: "1.0"`、`iss: https://sts.windows.net/<TENANT_ID>/`、`aud: api://<MIDDLE_TIER_ID>` |
| `/downstream/anything` に token A 付きでアクセス | エコーされた `Authorization` ヘッダーが token A と異なる token B になっている |
| token B をデコード | `aud` が downstream API、`scp` に `Data.Read` が含まれる |

## 検証後の後片付け

v1.0 受理は互換のための構成です。検証が終わったら、可能であれば標準構成（v2.0）へ戻すことを推奨します。

1. middle-tier アプリのマニフェストの `api.requestedAccessTokenVersion` を `2` に戻す（[ガイド 03 §3.2](03-entra-id-setup.md)）
2. `.env` の `DECK_AUDIENCE` を素の GUID（`<MIDDLE_TIER_ID>`）に戻す
3. `examples/kong.yaml` の `allow_v1_tokens: true` を再度コメントアウトする
4. `deck gateway sync examples/kong.yaml` で反映し、[ガイド 04（v2.0）](04-obo-verification-v2.md) の手順で動作を確認する

## うまくいかないとき

プラグインは失敗の詳細をレスポンスに含めず、debug ログにのみ出力します:

```bash
docker compose logs kong | grep "obo:"
```

v1.0 検証に固有の症状と対処:

| debug ログの理由 | 原因と対処 |
|---|---|
| `v1.0 token rejected: set requestedAccessTokenVersion=2 ...` | `allow_v1_tokens` が `false` のまま（§2 の `kong.yaml` のコメント解除漏れ、または `deck gateway sync` 忘れ） |
| `audience mismatch` | `DECK_AUDIENCE` が素の GUID のまま（v1.0 の `aud` は `api://` 形式。§2 と §5 の `aud` を突き合わせる） |
| `issuer mismatch` | token A が実は v2.0 形式（§1 の変更前に取得したキャッシュ済みトークン等）。§5 で `ver` を確認し、新しいトークンを取得し直す |
| （502 が返る） | v1.0 の OpenID メタデータ取得に失敗している。`allow_v1_tokens: true` では v1.0 メタデータの取得失敗は全体の失敗として扱われる（fail-close）ため、DP から `login.microsoftonline.com` への到達性を確認する |

上記以外の理由は [ガイド 03](03-entra-id-setup.md) の該当設定と `.env` の値（変更後は `deck gateway sync`）を見直してください。
