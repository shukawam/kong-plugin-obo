# ガイド 03: Entra ID のセットアップ

OBO フローに必要な 3 つのアプリを Microsoft Entra ID に登録します。

| アプリ | 役割 |
|---|---|
| ① クライアントアプリ | ユーザーを認証し、Kong 宛てのトークン（token A）を取得する |
| ② middle-tier アプリ | Kong Gateway（obo プラグイン）を表す。token A の `aud` はこのアプリ |
| ③ downstream API アプリ | Kong の背後の保護 API。交換後トークン（token B）の対象 |

作業は [Microsoft Entra admin center](https://entra.microsoft.com) で行います
（アプリ登録には最低 Application Developer ロールが必要）。

## 1. 3 つのアプリを登録する

それぞれについて:

1. **Entra ID > App registrations > New registration**
2. **Name** を入力（例: `obo-client` / `obo-middle-tier-kong` / `obo-downstream-api`）
3. **Supported account types** は **Single tenant only**（既定）
4. **Register** 後、**Overview** の **Application (client) ID** を控える

以降、①②③の client ID をそれぞれ `<CLIENT_APP_ID>` `<MIDDLE_TIER_ID>` `<DOWNSTREAM_ID>` と表記します。

## 2. downstream API アプリ（③）の設定

### 2.1 API とスコープを公開する

1. **Expose an API** → **Application ID URI** の **Add** → 既定値
   （`api://<DOWNSTREAM_ID>`）のまま **Save**
2. **Add a scope** で以下を入力して保存:
   - **Scope name**: `Data.Read`（任意の名前で可）
   - **Who can consent**: **Admins and users**
   - **Admin consent display name / description**: 任意の説明

スコープのフル文字列 `api://<DOWNSTREAM_ID>/Data.Read` が、
プラグインの `scopes` 設定（`.env` の `DECK_SCOPE`）に入れる値です。

### 2.2 middle-tier を事前承認する（OBO の同意要件）

OBO では middle-tier がユーザーと対話できないため、downstream への同意を
事前に構成する必要があります。テナント管理者権限が不要な方法:

1. 同じ **Expose an API** ページの **Authorized client applications** →
   **Add a client application**
2. **Client ID** に `<MIDDLE_TIER_ID>` を入力
3. **Authorized scopes** で `Data.Read` にチェックして追加

（テナント管理者に依頼できる場合は、middle-tier アプリの **API permissions** で
**Grant admin consent** を実行してもらう方法でも構いません）

## 3. middle-tier アプリ（②）の設定

### 3.1 クライアントシークレットを作成する

1. **Certificates & secrets > Client secrets > New client secret**
2. 説明と有効期限（推奨: 12 か月未満）を入力して **Add**
3. 表示された **Value** を控える（**ページを離れると二度と表示されません**）
   → `.env` の `DECK_CLIENT_SECRET` に設定する値

### 3.2 v2.0 アクセストークンの発行を設定する（必須）

1. **Manifest** ページを開く
2. `api` 属性に以下を追加して **Save**:

   ```json
   "api": {
       "requestedAccessTokenVersion": 2
   }
   ```

この設定により、このアプリ宛てに v2.0 形式のアクセストークンが発行されます
（未設定の場合は v1.0 形式が発行され、本プラグインのトークン検証を通りません）。

### 3.3 downstream API へのアクセス許可を追加する

1. **API permissions > Add a permission > My APIs**
2. downstream API アプリを選択 → **Delegated permissions** → `Data.Read` にチェック
3. **Add permissions**

### 3.4 自身のスコープを公開する

クライアントが「`aud` = middle-tier」の token A を取得するために必要です。

1. **Expose an API** → **Application ID URI** を既定値（`api://<MIDDLE_TIER_ID>`）で **Save**
2. **Add a scope** でスコープを追加:
   - **Scope name**: `access_as_user`
   - **Who can consent**: **Admins and users**

## 4. クライアントアプリ（①）の設定

1. **API permissions > Add a permission > My APIs** → middle-tier アプリ →
   **Delegated permissions** → `access_as_user` にチェック → **Add permissions**
2. **Authentication > Advanced settings > Allow public client flows** を **Yes** にする
   （[ガイド 04](04-obo-verification.md) の device code flow に必要）

## 5. `.env` に設定する値の対応表

| `.env` の変数 | 値 |
|---|---|
| `DECK_TENANT_ID` | テナント ID（GUID。任意のアプリの **Overview > Directory (tenant) ID**） |
| `DECK_CLIENT_ID` | `<MIDDLE_TIER_ID>` |
| `DECK_CLIENT_SECRET` | 3.1 で控えたシークレットの Value |
| `DECK_SCOPE` | `api://<DOWNSTREAM_ID>/Data.Read` |
| `DECK_AUDIENCE` | `<MIDDLE_TIER_ID>`（v2.0 トークンの `aud` は素の GUID） |

次: [ガイド 04: OBO トークン交換の確認](04-obo-verification.md)
