# kong-plugin-obo

Microsoft Entra ID の [On-Behalf-Of (OBO) フロー](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
を実現する Kong Gateway カスタムプラグインです。

## 1. 概要

`obo` プラグインは、Kong Gateway を OBO フローにおける「middle-tier API」として動作させます。
クライアントから受信したユーザーのアクセストークン（token A）を検証し、Entra ID との
OBO トークン交換によってダウンストリーム API 向けのアクセストークン（token B）を取得、
upstream へのリクエストの `Authorization` ヘッダーを token B に差し替えます。
これにより、バックエンド API はユーザーの委任スコープを保持したトークンを受け取れます。

```
クライアント                Kong (obo プラグイン)              Entra ID          バックエンド API
    │  ① Bearer token A ────▶ │                                  │                  │
    │                         │ ② token A 検証 (JWKS)            │                  │
    │                         │ ③ OBO リクエスト ───────────────▶│                  │
    │                         │ ④ ◀─────────────── token B ──────│                  │
    │                         │ ⑤ Authorization を token B に差し替え ──────────────▶│
```

処理の流れ:

1. `Authorization: Bearer <token A>` から受信トークンを取り出す。
2. JWKS を用いて受信トークンの署名・`iss`・`aud`・`exp`・`nbf` を検証する（認証）。
3. `required_scopes` / `required_roles` を設定している場合、受信トークンの `scp` / `roles` クレームが要件を満たすか検査する（認可）。満たさなければ `403`（`insufficient_scope`）で拒否し、トークン交換は行わない。未設定なら検査しない。
4. 交換済みトークンのキャッシュを確認し、なければ Entra ID のトークンエンドポイントへ
   OBO リクエスト（`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`,
   `requested_token_use=on_behalf_of`）を送って token B を取得する。
5. upstream へのリクエストの `Authorization` ヘッダーを `Bearer <token B>` に差し替える。
   受信した token A をそのまま upstream に転送することはない。

## 2. 前提: Entra ID 側のアプリ登録

このプラグインを使うには、Entra ID（Azure AD）に以下のアプリ登録が必要です。

- **middle-tier アプリ**（Kong Gateway を表すアプリ登録）を 1 つ作成する。
  - API のクライアント認証方式として `client_secret` または証明書（`private_key_jwt`）を設定する。
  - 「API のアクセス許可 (API permissions)」で、ダウンストリーム API に対する
    **委任スコープ (delegated scopes)** を追加する（アプリケーションロールではない）。
- **事前同意 (consent) が必須**。OBO フローでは middle-tier がユーザーと対話できないため、
  ダウンストリーム API への同意は事前に取得しておく必要がある。方法の例:
  - クライアントアプリの `knownClientApplications` に middle-tier を追加し、
    クライアント起点の同意で両アプリ分をまとめて同意させる（`.default` + combined consent）。
  - ダウンストリーム API 側のマニフェストで middle-tier を `preAuthorizedApplications` に
    宣言する。
  - テナント管理者による管理者同意 (admin consent) を付与する。

> **重要な注意（AADSTS70011）**: `.default` スコープを、`scopes` 設定に含めた他の委任スコープ
> （例: `User.Read` や `Mail.Read`）と同一リクエストで併用しないでください。併用すると
> Entra ID から `AADSTS70011` エラーが返ります。`.default` を使う場合は、原則としてそれ単独で
> 指定してください（`offline_access` のみ併用可能な場合があります）。本プラグインはこの制約を
> 機械的に検証しないため、`scopes` 設定を組み立てる際は運用者側で注意してください。

- OBO で交換できるのは **ユーザープリンシパルを表すアクセストークンのみ**です
  （サービスプリンシパルの app-only トークンは交換できません）。
- カスタム署名キーを設定したアプリ（SSO 用エンタープライズアプリ等）は middle-tier として
  使用できません。

## 3. インストールと有効化

### 3.1 対応バージョン

Kong Gateway **3.9.x** で開発・検証しています（CI では `3.9.x` / `stable` / 本番 DP と
同系の `3.14.0.7` をテスト）。
Kong OSS / Enterprise の両方で動作します（Enterprise ではシークレット系フィールドが
データベース上で暗号化されます）。

### 3.2 インストール

LuaRocks（luarocks.org）には未公開のため、リポジトリから直接インストールします。
Kong が使用する LuaRocks ツリーに対して実行してください。

```bash
git clone https://github.com/shukawam/kong-plugin-obo.git
cd kong-plugin-obo
luarocks make
```

コンテナ環境向けには、リポジトリ同梱の [`Dockerfile`](./Dockerfile) がこの手順を実行します
（「3.5 コンテナでの起動（Konnect データプレーン）」参照）。

### 3.3 プラグインの有効化

Kong にプラグインをロードさせるため、`kong.conf` または環境変数で `plugins` に `obo` を
追加して Kong を再起動します。

```bash
# kong.conf の場合
plugins = bundled,obo

# 環境変数の場合
export KONG_PLUGINS=bundled,obo
```

### 3.4 ルート/サービスへの適用

- **DB-less（declarative）モード**: 「5. 設定例」の YAML（`_format_version: "3.0"`）を
  そのまま宣言的設定ファイルとして使えます。
- **DB モード**: Admin API で適用します。

  ```bash
  curl -X POST http://localhost:8001/services/backend-api/plugins \
    --data name=obo \
    --data config.tenant_id=11111111-1111-1111-1111-111111111111 \
    --data config.client_id=22222222-2222-2222-2222-222222222222 \
    --data config.client_secret=<シークレット> \
    --data config.scopes[]=api://33333333-3333-3333-3333-333333333333/.default \
    --data config.audiences[]=22222222-2222-2222-2222-222222222222
  ```

### 3.5 コンテナでの起動（Konnect データプレーン）

リポジトリ同梱の `compose.yaml` は、obo プラグイン入りの Kong Gateway を
**Konnect のデータプレーン (DP)** として起動する構成です
（Observability スタック otel-lgtm も含みます）。

セットアップは以下のステップバイステップガイドに沿って、01 から順に実施してください:

1. [ガイド 01: カスタムプラグイン登録](./docs/01-custom-plugin-registration.md)
2. [ガイド 02: Data Plane のビルドと起動](./docs/02-data-plane-build.md)
3. [ガイド 03: Entra ID のセットアップ](./docs/03-entra-id-setup.md)
4. [ガイド 04: OBO トークン交換の確認](./docs/04-obo-verification.md)

切り分けには `compose.yaml` の `KONG_LOG_LEVEL: debug`（設定済み）のログを
`docker compose logs kong | grep "obo:"` で確認してください。

## 4. 設定リファレンス

`config.*` 以下の全フィールドです（`kong/plugins/obo/schema.lua` が正）。
「必須」は**利用者が明示的に値を設定する必要がある**項目のみに付けています。
既定値がある項目は省略可能です。

| 名前 | 型 | 必須 | 既定値 | 説明 |
|---|---|---|---|---|
| `tenant_id` | string | 必須 | - | Entra ID のテナント ID（GUID）またはテナントのドメイン名（`contoso.onmicrosoft.com` など）。メタデータ URL とトークンエンドポイントの導出に使う。単一テナント前提のため、マルチテナント別名（`common` / `organizations` / `consumers`）は不可。大文字は URL の導出時に小文字へ正規化される。ドメイン名を指定した場合、受信トークンの `iss` の期待値にはメタデータが返す正規化済みの GUID 形式 issuer が使われる。 |
| `client_id` | string | 必須 | - | middle-tier（この Kong Gateway）として登録したアプリのクライアント ID。 |
| `client_auth_method` | string (`client_secret` \| `private_key_jwt`) | 省略可 | `client_secret` | Entra ID へのクライアント認証方式。 |
| `client_secret` | string | 条件付き必須※1 | - | `client_auth_method = client_secret` のときのシークレット。Vault 参照（`{vault://...}`）可能、Kong EE では暗号化保存される。 |
| `private_key` | string | 条件付き必須※2 | - | `client_auth_method = private_key_jwt` のときの署名用秘密鍵（PEM 形式）。Vault 参照可能、Kong EE では暗号化保存される。 |
| `certificate_thumbprint` | string | 条件付き必須※2 | - | 証明書 DER の SHA-256 サムプリントを Base64url エンコードした値（`x5t#S256`。SHA-1 の `x5t` ではない）。client assertion のヘッダーに使用。 |
| `scopes` | array of string | 必須（最低 1 件） | - | 交換後トークンに要求するダウンストリーム API のスコープ。スペース区切りで `scope` パラメータに連結される。 |
| `audiences` | array of string | 必須（最低 1 件） | - | 受信トークンの `aud` クレームの期待値のリスト。いずれか 1 つと完全一致すれば受理。v2.0 トークンでは素の `client_id`、v1.0 トークンでは `api://{client_id}`（App ID URI）形式になることが多い。通常は `client_id` と同じ値を 1 件指定する。 |
| `allow_v1_tokens` | boolean | 省略可 | `false` | v1.0 形式のアクセストークン（`iss` が `https://sts.windows.net/{tid}/`、`ver` が `1.0`）も受理するか。有効時は v1.0 の OpenID メタデータも取得し、その検証済み issuer と `iss` を照合する。**まずはアプリ登録の `api.requestedAccessTokenVersion` を `2` にして v2.0 トークンへ移行することを推奨**。これはアプリ登録を変更できない環境向けの設定。 |
| `issuer` | string | 任意 | - | **v2.0** OpenID メタデータの `issuer` に対するピン（追加の防御）。`allow_v1_tokens` 有効時も常に v2.0 メタデータの issuer を指定する（v1.0 の `https://sts.windows.net/...` を設定するとメタデータ検証が失敗し 502 になる）。設定時、メタデータの `issuer` がこの値と完全一致しない場合はリクエストを拒否する。受信トークンの `iss` クレームは常に**検証済みメタデータの `issuer`** と完全一致を要求されるため、この値で `iss` の期待値を別の値に差し替えることはできない。 |
| `required_scopes` | array of string | 任意 | - | 受信トークンの `scp`（委任スコープ）クレームに含まれていなければならないスコープのリスト。設定すると、指定した全スコープを持たないトークンを `403`（`insufficient_scope`）で拒否する。`scp` はユーザートークンにのみ含まれるため、これを設定すると `scp` を持たない app-only / daemon トークンも拒否される。**未設定なら `scp` の検査は行わない**（下記の注記を参照）。 |
| `required_roles` | array of string | 任意 | - | 受信トークンの `roles`（アプリロール）クレームに含まれていなければならないロールのリスト。設定すると、指定した全ロールを持たないトークンを `403` で拒否する。未設定なら検査しない。`roles` は app-only トークンにもユーザーの割当ロールにも現れるため、これのみ設定した場合も**非空の `scp` クレームの存在**を併せて要求し、`scp` を持たない app-only / ID トークンは `403` で拒否する（`scp` の値の照合はしない。OBO はユーザー委任トークン専用のため）。要素は app role の「Value」（空白を含められない）を指定する。 |
| `identity_base_url` | url | 省略可 | `https://login.microsoftonline.com` | Entra ID のベース URL。通常は変更不要（ソブリンクラウドやテストで使用）。末尾スラッシュは自動で正規化される。**本番では必ず `https://` を指定する**（`http://` はモック IdP を使う統合テスト用）。 |
| `token_cache_enabled` | boolean | 省略可 | `true` | 交換済みトークンをキャッシュするか。 |
| `cache_ttl_margin` | integer (`>= 0`) | 省略可 | `30` | キャッシュ TTL を `expires_in` から何秒差し引くか（期限ギリギリのトークンを使わないための余裕、秒）。 |
| `http_timeout` | integer (`> 0`) | 省略可 | `10000` | Entra ID への HTTP タイムアウト（ミリ秒）。 |
| `ssl_verify` | boolean | 省略可 | `true` | Entra ID への接続で TLS 証明書を検証するか（本番では必ず `true`）。 |

※1 `client_auth_method = client_secret` のとき `client_secret` が必須（`entity_checks`）。
※2 `client_auth_method = private_key_jwt` のとき `private_key` と `certificate_thumbprint` の両方が必須（`entity_checks`）。

> **認可（`required_scopes` / `required_roles`）についての注意**: これらを設定しない場合、
> プラグインは受信トークンの `scp` / `roles` を一切検査しません（署名・`iss`・`aud`・`exp`・`nbf`
> の**認証**のみを行います）。この場合、ルートへのアクセス認可は別のプラグイン（例: ACL や
> OPA 連携）や downstream API 側で行ってください。特定の委任スコープを持つユーザートークンだけを
> 通したい場合は `required_scopes` を設定してください（`scp` を持たない app-only トークンも
> 併せて拒否されます）。権限不足のトークンは認証失敗（`401`）ではなく `403`（`insufficient_scope`,
> [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) §3.1）で拒否されます。
> なお、明示的な**空配列**（`required_scopes: []` 等）は「検査なし」ではなく**設定エラー**として
> スキーマ検証で拒否されます（値の入れ忘れが認可スキップにつながるのを防ぐため。設定するなら 1 件以上必須）。

### 4.1 運用上の注意

- **`ssl_verify = false` と `http://` の `identity_base_url` は統合テスト専用**: これらはモック IdP を使う統合テスト専用の設定です。本番環境では `identity_base_url` に `https://` を指定し、`ssl_verify` を既定の `true` のままにしてください。プラグインは受信トークンの検証時に、メタデータ（OpenID configuration）の `issuer` が取得元と整合すること、`jwks_uri` が `identity_base_url` と同一ホストの HTTPS であること、受信トークンの `iss` がメタデータの `issuer` と完全一致することを検証します（`identity_base_url` が `http://` の場合のみ `jwks_uri` の `http://` を許容）。
- **交換済みトークン（token B）は共有メモリに平文で保持される**: `token_cache_enabled`
  が既定値の `true` の場合、交換済みトークンは `kong.cache`（Kong Gateway のワーカー間
  共有メモリキャッシュ）に保持されます（`kong/plugins/obo/token_cache.lua`）。
  キャッシュキーは受信トークン・`client_id`・`scopes`・テナント情報から SHA-256 で
  ハッシュ化した値ですが、キャッシュの**値**（token B 本体）は平文のままです。
  これは Kong の標準的な認証系プラグインと同等の設計ですが、同一ノード上で動作する他の
  プラグインや Lua コードから理論上参照できる可能性がある点に留意してください。
  この挙動を避けたい場合は `token_cache_enabled = false` に設定してください
  （代わりにリクエストのたびに Entra ID へ交換リクエストが発生し、レイテンシと
  レート制限に影響します）。
- **スキーマに露出していないハードコード既定値**: 以下の値は `config.*` として
  設定できず、現時点ではコード内の定数として固定されています。
  - 受信トークンの `exp` / `nbf` 検証で許容するクロックスキュー: **60 秒**
    （`kong/plugins/obo/jwt_validator.lua` の `CLOCK_SKEW`）。
  - OpenID 設定 / JWKS の `kong.cache` 上のキャッシュ TTL: **3600 秒**
    （`kong/plugins/obo/jwt_validator.lua` の `METADATA_TTL`）。
  - 未知の `kid` を受けた際に、既存の鍵セットを保持したまま `kong.cache:renew` で JWKS を
    再取得・更新するデバウンス間隔: **30 秒**、かつ **Kong のワーカープロセス単位**
    （クラスタ全体では共有されないため、ワーカーごとに独立してこの間隔が適用される）。
    再取得に失敗した場合は既存の鍵セットを使い続ける
    （`kong/plugins/obo/jwt_validator.lua` の `JWKS_REFETCH_INTERVAL` / `last_refetch`）。

## 5. 設定例

### 5.1 client_secret 方式

```yaml
_format_version: "3.0"

services:
  - name: backend-api
    url: https://backend.internal.example.com

    routes:
      - name: backend-api-route
        paths:
          - /api

    plugins:
      - name: obo
        config:
          tenant_id: 11111111-1111-1111-1111-111111111111
          client_id: 22222222-2222-2222-2222-222222222222
          client_auth_method: client_secret
          client_secret: "{vault://env/OBO_CLIENT_SECRET}"
          scopes:
            - api://33333333-3333-3333-3333-333333333333/.default
          audiences:
            - 22222222-2222-2222-2222-222222222222
```

### 5.2 private_key_jwt 方式

`certificate_thumbprint` は証明書の **DER エンコーディングの SHA-256 サムプリントを
Base64url エンコードした値**（`x5t#S256`）です。SHA-1 の `x5t` ではない点に注意してください。

```yaml
_format_version: "3.0"

services:
  - name: backend-api
    url: https://backend.internal.example.com

    routes:
      - name: backend-api-route
        paths:
          - /api

    plugins:
      - name: obo
        config:
          tenant_id: 11111111-1111-1111-1111-111111111111
          client_id: 22222222-2222-2222-2222-222222222222
          client_auth_method: private_key_jwt
          private_key: "{vault://env/OBO_PRIVATE_KEY_PEM}"
          certificate_thumbprint: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfG"
          scopes:
            - User.Read
            - Mail.Read
          audiences:
            - 22222222-2222-2222-2222-222222222222
```

## 6. エラー

このプラグインが `access` フェーズで返しうる主なレスポンスです。内部の詳細な失敗理由は
レスポンスボディに含めず（`debug` ログにのみ出力）、認証系プラグインの慣例に従います。

| ステータス | 意味 |
|---|---|
| `401 Unauthorized` | `Authorization` ヘッダーがない/`Bearer` 形式でない、受信トークンの検証失敗（署名・`iss`・`aud`・`exp`・`nbf`・`ver` 不一致。`allow_v1_tokens` 無効時の v1.0 トークンや `ver` 欠落・未知の値も含む）、または Entra ID がトークン交換を拒否した場合。`WWW-Authenticate` ヘッダーに、無害化した OAuth エラーコードと（Entra ID が返した場合）Base64 エンコードされたクレームチャレンジ（`claims`）を付与する。 |
| `403 Forbidden` | トークンの**認証**は成功したが、`required_scopes` / `required_roles` で要求した委任スコープ（`scp`）・アプリロール（`roles`）を満たさない場合（権限不足）。`WWW-Authenticate: Bearer error="insufficient_scope"` を付与する（[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) §3.1）。どのスコープ/ロールが不足したかはレスポンスに含めない。 |
| `502 Bad Gateway` | Entra ID への到達性・応答に問題がある場合（OpenID configuration/JWKS の取得失敗、トークン交換リクエストでの IdP 側 5xx やネットワークエラーなど）。受信トークン自体の検証結果ではなく IdP 側の障害であることを示す。 |
| `500 Internal Server Error` | 上記以外の想定外のエラー。 |

## 7. 開発

テストは `kong-pongo` 上で実行します。詳細な運用ルール・アーキテクチャ・コーディング規約は
[`CLAUDE.md`](./CLAUDE.md) を参照してください。

```bash
pongo up      # 依存コンテナ（Postgres）起動
pongo run     # 全テスト実行（単体 + 統合）
pongo lint    # luacheck 実行
pongo down    # コンテナ停止
```

リリース手順（バージョン更新とタグ作成）は [`docs/05-release.md`](./docs/05-release.md) を参照してください。

## 8. 参考資料（一次情報）

本プラグインのプロトコル実装は、以下の一次情報に基づいています。

- [Microsoft identity platform and OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow) — OBO フロー本体（リクエスト/レスポンス/制限事項）
- [Microsoft identity platform application authentication certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) — client assertion（`private_key_jwt`、PS256 / `x5t#S256`）の仕様
- [Access tokens in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens) — 受信トークンの検証方法・署名鍵ロールオーバー
- [OpenID Connect on the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) — OpenID configuration / JWKS エンドポイント
- [Access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference) — `scp`（スペース区切りのスコープ文字列、ユーザートークンのみ）/ `roles`（文字列の配列）の形式
- [Secure applications and APIs by validating claims](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation) — `scp` / `roles` による認可、`scp` 欠落（app-only / daemon / id_token）の扱い
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) — Bearer トークンの `WWW-Authenticate` 応答と `insufficient_scope`（403）
- [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) — jwt-bearer グラントと client assertion の土台仕様

> **コード内コメントの `docs/obo/0X` 参照について**: ソースコードのコメントは、上記一次情報を
> 裏取り・整理したローカル専用の仕様ノート `docs/obo/`（Git 管理外）を参照しています。
> 対応関係は次のとおりです: `01`〜`03`, `06` → OBO フロー本体のドキュメント、
> `04` → certificate credentials、`05` → access tokens / OIDC メタデータ、
> `07` → RFC 7521/7523。リポジトリをクローンした環境では上記 URL を直接参照してください。
