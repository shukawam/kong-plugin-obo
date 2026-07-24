# Guide 03: Setting up Entra ID

[日本語](../../03-entra-id-setup.md) | **English**

Register the three apps required for the OBO flow in Microsoft Entra ID.

| App | Role |
|---|---|
| ① Client app | Authenticates the user and obtains a token for Kong (token A) |
| ② Middle-tier app | Represents Kong Gateway (the obo plugin). The `aud` of token A is this app |
| ③ Downstream API app | The protected API behind Kong. The target of the exchanged token (token B) |

Do this work in the [Microsoft Entra admin center](https://entra.microsoft.com) (registering an app requires at least the "Application Developer" role). The UI labels below follow the English portal.

## 1. Register the three apps

For each of them:

1. **Entra ID > App registrations > New registration**
2. Enter a **Name** (e.g. `obo-client` / `obo-middle-tier-kong` / `obo-downstream-api`)
3. For **Supported account types**, choose **Accounts in this organizational directory only** (single tenant; the default)
4. After **Register**, note the **Application (client) ID** on the **Overview** page

Below, the client IDs of apps 1, 2, and 3 are denoted `<CLIENT_APP_ID>`, `<MIDDLE_TIER_ID>`, and `<DOWNSTREAM_ID>` respectively.

## 2. Configure the downstream API app (3)

### 2.1 Expose an API and a scope

1. **Expose an API** → **Add** next to **Application ID URI** → keep the default (`api://<DOWNSTREAM_ID>`) and **Save**
2. **Add a scope** and save with the following:
   - **Scope name**: `Data.Read` (any name is fine)
   - **Who can consent**: **Admins and users**
   - **Admin consent display name / Admin consent description**: any description

The full scope string `api://<DOWNSTREAM_ID>/Data.Read` is the value you put in the plugin's `scopes` setting (`DECK_SCOPE` in `.env`).

### 2.2 Pre-authorize the middle-tier (OBO consent requirement)

Because the middle-tier cannot interact with the user in an OBO flow, consent to the downstream must be configured in advance. A method that does not require tenant-admin privileges:

1. On the same **Expose an API** page, **Authorized client applications** → **Add a client application**
2. Enter `<MIDDLE_TIER_ID>` for the **Application (client) ID**
3. Check `Data.Read` under **Authorized scopes** and click **Add application**

(If you can ask a tenant admin, an alternative is to have them run **Grant admin consent for \<tenant\>** under the middle-tier app's **API permissions**.)

## 3. Configure the middle-tier app (2)

### 3.1 Create a client secret

1. **Certificates & secrets > Client secrets > New client secret**
2. Enter a description and expiry (recommended: under 12 months) and click **Add**
3. Record the displayed **Value** (**it is never shown again once you leave the page**) → the value to set for `DECK_CLIENT_SECRET` in `.env`

### 3.2 Configure v2.0 access token issuance (recommended)

1. Open the **Manifest** page
2. Add the following to the `api` attribute and **Save**:

   ```json
   "api": {
       "requestedAccessTokenVersion": 2
   }
   ```

This setting makes access tokens for this app be issued in the v2.0 format (when unset, the v1.0 format is issued, which is rejected by the plugin's default configuration (`allow_v1_tokens: false`)).

If you have a reason you cannot change the app registration manifest, you can instead configure the plugin with `allow_v1_tokens: true` to accept v1.0-format tokens (in that case the incoming token's `aud` is often in the `api://{client_id}` form, so include that value in `audiences`). If possible, prefer changing the manifest (migrating to v2.0). For the verification procedure with v1.0 tokens, see [Guide 04-v1: Verifying OBO token exchange (v1.0 tokens)](04-obo-verification-v1.md).

### 3.3 Add permission to the downstream API

1. **API permissions > Add a permission > My APIs**
2. Select the downstream API app → **Delegated permissions** → check `Data.Read`
3. **Add permissions**

### 3.4 Expose your own scope

This is required so that the client can obtain token A with `aud` = middle-tier.

1. **Expose an API** → **Save** the **Application ID URI** with the default (`api://<MIDDLE_TIER_ID>`)
2. **Add a scope**:
   - **Scope name**: `access_as_user`
   - **Who can consent**: **Admins and users**

> **Note**: A newly exposed scope can take a few minutes to appear in another app's "Add a permission" list. If `access_as_user` is not selectable in §4, wait a few minutes and reload the page.

## 4. Configure the client app (1)

1. **API permissions > Add a permission > My APIs** → the middle-tier app → **Delegated permissions** → check `access_as_user` → **Add permissions**
2. Set **Authentication > Advanced settings > Allow public client flows** to **Yes** (required for the device code flow in [Guide 04](04-obo-verification-v2.md))

## 5. Mapping of values to set in `.env`

| `.env` variable | Value |
|---|---|
| `DECK_TENANT_ID` | Tenant ID (GUID; **Overview > Directory (tenant) ID** of any app) |
| `DECK_CLIENT_ID` | `<MIDDLE_TIER_ID>` |
| `DECK_CLIENT_SECRET` | The secret value recorded in 3.1 |
| `DECK_SCOPE` | `api://<DOWNSTREAM_ID>/Data.Read` |
| `DECK_AUDIENCE` | `<MIDDLE_TIER_ID>` (the `aud` of a v2.0 token is the bare GUID) |
| `CLIENT_APP_ID` | `<CLIENT_APP_ID>` (used to obtain the token in [Guide 04](04-obo-verification-v2.md)) |

Next: [Guide 04: Verifying OBO token exchange (v2.0 tokens, standard setup)](04-obo-verification-v2.md) (to verify with v1.0 tokens, see [Guide 04-v1](04-obo-verification-v1.md))
