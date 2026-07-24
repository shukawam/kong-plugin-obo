# kong-plugin-obo

[日本語](../../../README.md) | **English**

A Kong Gateway custom plugin that implements the Microsoft Entra ID [On-Behalf-Of (OBO) flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow).

## 1. Overview

The `obo` plugin makes Kong Gateway act as the "middle-tier API" in the OBO flow. It validates the user's access token received from the client (token A), obtains a downstream-API access token (token B) via OBO token exchange with Entra ID, and swaps the `Authorization` header of the upstream request to token B. This lets the backend API receive a token that preserves the user's delegated scopes.

```
Client                      Kong (obo plugin)                  Entra ID          Backend API
    │  ① Bearer token A ────▶ │                                  │                  │
    │                         │ ② validate token A (JWKS)        │                  │
    │                         │ ③ OBO request ──────────────────▶│                  │
    │                         │ ④ ◀─────────────── token B ──────│                  │
    │                         │ ⑤ swap Authorization to token B ────────────────────▶│
```

Flow of processing:

1. Extract the incoming token from `Authorization: Bearer <token A>`.
2. Validate the incoming token's signature, `iss`, `aud`, `exp`, and `nbf` using JWKS (authentication).
3. If `required_scopes` / `required_roles` are configured, check whether the incoming token's `scp` / `roles` claims meet the requirements (authorization). If not, reject with `403` (`insufficient_scope`) and do not perform token exchange. If unset, no check is done.
4. Check the exchanged-token cache; if absent, send an OBO request (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `requested_token_use=on_behalf_of`) to Entra ID's token endpoint to obtain token B.
5. Swap the `Authorization` header of the upstream request to `Bearer <token B>`. The incoming token A is never forwarded to the upstream as-is.

## 2. Prerequisites: app registration on the Entra ID side

To use this plugin, you need the following app registrations in Entra ID (Azure AD).

- Create one **middle-tier app** (the app registration that represents Kong Gateway).
  - Set the API's client authentication method to `client_secret` or a certificate (`private_key_jwt`).
  - Under "API permissions", add **delegated scopes** for the downstream API (not application roles).
- **Pre-consent is required.** Because the middle-tier cannot interact with the user in an OBO flow, consent to the downstream API must be obtained in advance. Example methods:
  - Add the middle-tier to the client app's `knownClientApplications` and consent to both apps together via client-initiated consent (`.default` + combined consent).
  - Declare the middle-tier in the downstream API's manifest under `preAuthorizedApplications`.
  - Grant admin consent by a tenant administrator.

> **Important note (AADSTS70011)**: Do not combine the `.default` scope with other delegated scopes (e.g. `User.Read` or `Mail.Read`) in the same request. Doing so returns an `AADSTS70011` error from Entra ID. When using `.default`, specify it on its own as a rule (in some cases only `offline_access` may be combined). This plugin does not mechanically validate this constraint, so take care when building the `scopes` setting.

- OBO can only exchange **access tokens that represent a user principal** (app-only tokens of a service principal cannot be exchanged).
- An app configured with a custom signing key (such as an enterprise app for SSO) cannot be used as the middle-tier.

## 3. Installation and enablement

### 3.1 Supported versions

Developed and verified with Kong Gateway **3.9.x** (CI tests `3.9.x` / `stable` / and `3.14.0.7`, which is in the same line as the production DP). It works with both Kong OSS and Enterprise (on Enterprise, secret fields are encrypted in the database).

### 3.2 Installation

Since it is not published on LuaRocks (luarocks.org), install directly from the repository. Run against the LuaRocks tree that Kong uses.

```bash
git clone https://github.com/shukawam/kong-plugin-obo.git
cd kong-plugin-obo
luarocks make
```

For container environments, the [`Dockerfile`](../../../Dockerfile) bundled in the repository runs this procedure (see "3.5 Starting in a container (Konnect Data Plane)").

### 3.3 Enabling the plugin

To make Kong load the plugin, add `obo` to `plugins` in `kong.conf` or via an environment variable, and restart Kong.

```bash
# In kong.conf
plugins = bundled,obo

# Via environment variable
export KONG_PLUGINS=bundled,obo
```

### 3.4 Applying to a route/service

- **DB-less (declarative) mode**: You can use the YAML in "5. Configuration examples" (`_format_version: "3.0"`) directly as a declarative config file.
- **DB mode**: Apply it via the Admin API.

  ```bash
  curl -X POST http://localhost:8001/services/backend-api/plugins \
    --data name=obo \
    --data config.tenant_id=11111111-1111-1111-1111-111111111111 \
    --data config.client_id=22222222-2222-2222-2222-222222222222 \
    --data config.client_secret=<secret> \
    --data config.scopes[]=api://33333333-3333-3333-3333-333333333333/.default \
    --data config.audiences[]=22222222-2222-2222-2222-222222222222
  ```

### 3.5 Starting in a container (Konnect Data Plane)

The `compose.yaml` bundled in the repository is a setup that starts a Kong Gateway with the obo plugin as a **Konnect Data Plane (DP)** (it also includes the observability stack otel-lgtm).

Follow the step-by-step guides below in order, starting from 01:

1. [Guide 01: Registering the custom plugin](01-custom-plugin-registration.md)
2. [Guide 02: Building and starting the Data Plane](02-data-plane-build.md)
3. [Guide 03: Setting up Entra ID](03-entra-id-setup.md)
4. [Guide 04: Verifying OBO token exchange (v2.0 tokens, standard setup)](04-obo-verification-v2.md)
   - To verify with v1.0-format tokens (`allow_v1_tokens`): [Guide 04-v1](04-obo-verification-v1.md)

For troubleshooting, check the logs from `KONG_LOG_LEVEL: debug` in `compose.yaml` (already set) with `docker compose logs kong | grep "obo:"`.

## 4. Configuration reference

All fields under `config.*` (`kong/plugins/obo/schema.lua` is authoritative). "Required" is marked only on items **the operator must explicitly set a value for**. Items with a default value may be omitted.

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `tenant_id` | string | Required | - | The Entra ID tenant ID (GUID) or the tenant's domain name (e.g. `contoso.onmicrosoft.com`). Used to derive the metadata URL and token endpoint. Single-tenant is assumed, so multi-tenant aliases (`common` / `organizations` / `consumers`) are not allowed. Uppercase is normalized to lowercase when deriving the URL. If a domain name is specified, the expected value for the incoming token's `iss` is the normalized GUID-form issuer returned by the metadata. |
| `client_id` | string | Required | - | The client ID of the app registered as the middle-tier (this Kong Gateway). |
| `client_auth_method` | string (`client_secret` \| `private_key_jwt`) | Optional | `client_secret` | The client authentication method to Entra ID. |
| `client_secret` | string | Conditionally required ※1 | - | The secret used when `client_auth_method = client_secret`. Can be a Vault reference (`{vault://...}`); stored encrypted on Kong EE. |
| `private_key` | string | Conditionally required ※2 | - | The signing private key (PEM format) used when `client_auth_method = private_key_jwt`. Can be a Vault reference; stored encrypted on Kong EE. |
| `certificate_thumbprint` | string | Conditionally required ※2 | - | The Base64url-encoded SHA-256 thumbprint of the certificate DER (`x5t#S256`, not the SHA-1 `x5t`). Used in the client assertion header. |
| `scopes` | array of string | Required (at least 1) | - | The downstream-API scopes to request for the exchanged token. Joined with spaces into the `scope` parameter. |
| `audiences` | array of string | Required (at least 1) | - | The list of expected values for the incoming token's `aud` claim. Accepted if it exactly matches any one of them. For v2.0 tokens this is often the bare `client_id`; for v1.0 tokens the `api://{client_id}` (App ID URI) form. Typically specify a single value equal to `client_id`. |
| `allow_v1_tokens` | boolean | Optional | `false` | Whether to also accept v1.0-format access tokens (`iss` is `https://sts.windows.net/{tid}/`, `ver` is `1.0`). When enabled, the v1.0 OpenID metadata is also fetched and its validated issuer is matched against `iss`. **First, prefer migrating to v2.0 tokens by setting the app registration's `api.requestedAccessTokenVersion` to `2`.** This setting is for environments that cannot change the app registration. |
| `issuer` | string | Optional | - | A pin (defense in depth) against the **v2.0** OpenID metadata's `issuer`. Always specify the v2.0 metadata issuer, even when `allow_v1_tokens` is enabled (setting the v1.0 `https://sts.windows.net/...` makes metadata validation fail with a 502). When set, the request is rejected if the metadata's `issuer` does not exactly match this value. The incoming token's `iss` claim is always required to exactly match the **validated metadata's `issuer`**, so this value cannot substitute a different expected value for `iss`. |
| `required_scopes` | array of string | Optional | - | The list of scopes that must be present in the incoming token's `scp` (delegated scopes) claim. When set, a token that lacks all of the specified scopes is rejected with `403` (`insufficient_scope`). Since `scp` appears only in user tokens, setting this also rejects app-only / daemon tokens that have no `scp`. **If unset, no check on `scp` is done** (see the note below). |
| `required_roles` | array of string | Optional | - | The list of roles that must be present in the incoming token's `roles` (app roles) claim. When set, a token that lacks all of the specified roles is rejected with `403`. If unset, no check is done. Because `roles` appears in both app-only tokens and users' assigned roles, setting only this also requires the **presence of a non-empty `scp` claim**, rejecting app-only / ID tokens without `scp` with `403` (the `scp` values are not matched; OBO is for user-delegated tokens only). Specify each element as the app role's "Value" (which cannot contain whitespace). |
| `identity_base_url` | url | Optional | `https://login.microsoftonline.com` | The Entra ID base URL. Usually no change is needed (used for sovereign clouds or testing). A trailing slash is normalized automatically. **Always specify `https://` in production** (`http://` is for integration tests using a mock IdP). |
| `token_cache_enabled` | boolean | Optional | `true` | Whether to cache exchanged tokens. |
| `cache_ttl_margin` | integer (`>= 0`) | Optional | `30` | How many seconds to subtract from `expires_in` for the cache TTL (a margin, in seconds, to avoid using a token that is about to expire). |
| `http_timeout` | integer (`> 0`) | Optional | `10000` | The HTTP timeout to Entra ID (in milliseconds). |
| `ssl_verify` | boolean | Optional | `true` | Whether to verify the TLS certificate when connecting to Entra ID (always `true` in production). |

※1 `client_secret` is required when `client_auth_method = client_secret` (`entity_checks`).
※2 Both `private_key` and `certificate_thumbprint` are required when `client_auth_method = private_key_jwt` (`entity_checks`).

> **Note on authorization (`required_scopes` / `required_roles`)**: If you do not set these, the plugin does not inspect the incoming token's `scp` / `roles` at all (it only performs **authentication** of the signature, `iss`, `aud`, `exp`, and `nbf`). In that case, authorize access to the route with another plugin (e.g. ACL or an OPA integration) or on the downstream API side. If you want to let through only user tokens that have specific delegated scopes, set `required_scopes` (app-only tokens without `scp` are also rejected). Tokens with insufficient privileges are rejected not as an authentication failure (`401`) but with `403` (`insufficient_scope`, [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) §3.1). Note that an explicit **empty array** (`required_scopes: []`, etc.) is not "no check" but a **configuration error** rejected by schema validation (to prevent a forgotten value from silently skipping authorization; if you set it, at least 1 element is required).

### 4.1 Operational notes

- **`ssl_verify = false` and an `http://` `identity_base_url` are for integration tests only**: these are settings for integration tests using a mock IdP. In production, specify `https://` for `identity_base_url` and leave `ssl_verify` at its default `true`. When validating the incoming token, the plugin verifies that the metadata (OpenID configuration) `issuer` is consistent with where it was fetched, that `jwks_uri` is HTTPS on the same host as `identity_base_url`, and that the incoming token's `iss` exactly matches the metadata's `issuer` (an `http://` `jwks_uri` is allowed only when `identity_base_url` is `http://`).
- **Exchanged tokens (token B) are held in shared memory in plaintext**: when `token_cache_enabled` is at its default `true`, exchanged tokens are held in `kong.cache` (Kong Gateway's inter-worker shared memory cache) (`kong/plugins/obo/token_cache.lua`). The cache key is a SHA-256 hash of the incoming token, `client_id`, `scopes`, and tenant info, but the cache **value** (token B itself) is in plaintext. This is equivalent in design to Kong's standard authentication plugins, but be aware that it could in theory be read by other plugins or Lua code running on the same node. To avoid this behavior, set `token_cache_enabled = false` (in exchange, an exchange request to Entra ID occurs on every request, affecting latency and rate limits).
- **Hardcoded defaults not exposed in the schema**: the following values cannot be set as `config.*` and are currently fixed as constants in the code.
  - The clock skew allowed when validating the incoming token's `exp` / `nbf`: **60 seconds** (`CLOCK_SKEW` in `kong/plugins/obo/jwt_validator.lua`).
  - The cache TTL in `kong.cache` for the OpenID configuration / JWKS: **3600 seconds** (`METADATA_TTL` in `kong/plugins/obo/jwt_validator.lua`).
  - The debounce interval for re-fetching and updating JWKS via `kong.cache:renew` (while keeping the existing key set) when an unknown `kid` is received: **30 seconds**, and **per Kong worker process** (it is not shared across the cluster, so each worker applies this interval independently). If the re-fetch fails, it keeps using the existing key set (`JWKS_REFETCH_INTERVAL` / `last_refetch` in `kong/plugins/obo/jwt_validator.lua`).

## 5. Configuration examples

### 5.1 client_secret method

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

### 5.2 private_key_jwt method

`certificate_thumbprint` is the **Base64url-encoded SHA-256 thumbprint of the certificate's DER encoding** (`x5t#S256`). Note that it is not the SHA-1 `x5t`.

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

## 6. Errors

The main responses this plugin may return in the `access` phase. Internal failure details are not included in the response body (only emitted to the `debug` log), following the convention of authentication plugins.

| Status | Meaning |
|---|---|
| `401 Unauthorized` | No `Authorization` header / not `Bearer` format, incoming-token validation failure (signature, `iss`, `aud`, `exp`, `nbf`, `ver` mismatch; including v1.0 tokens when `allow_v1_tokens` is disabled and a missing or unknown `ver`), or Entra ID rejected the token exchange. The `WWW-Authenticate` header carries a sanitized OAuth error code and (if Entra ID returned one) a Base64-encoded claims challenge (`claims`). |
| `403 Forbidden` | The token's **authentication** succeeded, but it does not satisfy the delegated scopes (`scp`) / app roles (`roles`) required by `required_scopes` / `required_roles` (insufficient privileges). Carries `WWW-Authenticate: Bearer error="insufficient_scope"` ([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) §3.1). Which scope/role was missing is not included in the response. |
| `502 Bad Gateway` | A reachability/response problem with Entra ID (failure to fetch the OpenID configuration/JWKS, an IdP-side 5xx or network error on the token exchange request, etc.). Indicates an IdP-side failure rather than a validation result of the incoming token itself. |
| `500 Internal Server Error` | Any other unexpected error. |

## 7. Development

Tests run on `kong-pongo`. For detailed operational rules, architecture, and coding conventions, see [`CLAUDE.md`](../../../CLAUDE.md).

```bash
pongo up      # start dependency containers (Postgres)
pongo run     # run all tests (unit + integration)
pongo lint    # run luacheck
pongo down    # stop the containers
```

For the release procedure (version bump and tag creation), see [`docs/05-release.md`](05-release.md).

## 8. References (primary sources)

This plugin's protocol implementation is based on the following primary sources.

- [Microsoft identity platform and OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow) — the OBO flow itself (request/response/limitations)
- [Microsoft identity platform application authentication certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) — the client assertion (`private_key_jwt`, PS256 / `x5t#S256`) spec
- [Access tokens in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens) — how to validate the incoming token, signing key rollover
- [OpenID Connect on the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) — the OpenID configuration / JWKS endpoints
- [Access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference) — the format of `scp` (a space-separated scope string, user tokens only) / `roles` (an array of strings)
- [Secure applications and APIs by validating claims](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation) — authorization via `scp` / `roles`, handling of a missing `scp` (app-only / daemon / id_token)
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) — the `WWW-Authenticate` response for Bearer tokens and `insufficient_scope` (403)
- [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) — the foundational specs for the jwt-bearer grant and client assertion

> **On the `docs/obo/0X` references in code comments**: the source code comments reference local-only spec notes in `docs/obo/` (not under Git management) that back up and organize the primary sources above. The correspondence is: `01`–`03`, `06` → the OBO flow documentation, `04` → certificate credentials, `05` → access tokens / OIDC metadata, `07` → RFC 7521/7523. In a cloned environment, refer to the URLs above directly.
