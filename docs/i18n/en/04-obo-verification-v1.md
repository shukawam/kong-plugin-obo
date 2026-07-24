# Guide 04-v1: Verifying OBO token exchange (v1.0 tokens)

[日本語](../../04-obo-verification-v1.md) | **English**

Reproduce an environment where **v1.0-format access tokens** (`ver: "1.0"`, `iss: https://sts.windows.net/{tid}/`) arrive from the client, and confirm that an obo plugin configured with `allow_v1_tokens: true` can validate them and perform token exchange.

To verify the standard setup (v2.0 tokens), use [Guide 04: Verifying OBO token exchange (v2.0 tokens, standard setup)](04-obo-verification-v2.md). Accepting v1.0 tokens is a configuration for environments that cannot change the app registration manifest; if possible, prefer `requestedAccessTokenVersion: 2` (migrating to v2.0) ([Guide 03 §3.2](03-entra-id-setup.md)).

## Prerequisites

- [Guide 01](01-custom-plugin-registration.md) through [03](03-entra-id-setup.md) completed (§1–2 of this guide changes part of the Guide 03 setup for v1.0)
- Tools: `curl` / `jq` / `deck` / the `jwt` command from [jwt-cli](https://github.com/mike-engel/jwt-cli) (treated as required in this guide, since it is used to check the token version)
- All variables in `.env` filled in (see the mapping in [Guide 03 §5](03-entra-id-setup.md))
- `DECK_DOWNSTREAM_URL` in `.env` set to the base URL of the downstream API that is token B's actual audience. If the downstream API registered in [Guide 03](03-entra-id-setup.md) is a test app with no real service, set the request-echo API `https://httpbin.org` (so you can inspect token B's contents in §6–7)

## Steps

### 1. Make the middle-tier app issue v1.0 tokens

The token version is determined solely by the **`api.requestedAccessTokenVersion` in the receiving (middle-tier) app registration's manifest**, not by the client's library or the endpoint used (`null` or `1` → v1.0, `2` → v2.0).

1. In the Entra admin center, open the **Manifest** page of the **middle-tier app**
2. Set `api.requestedAccessTokenVersion` to `null` (the default) or `1` and **Save** (revert it if you set `2` in [Guide 03 §3.2](03-entra-id-setup.md))

```json
"api": {
    "requestedAccessTokenVersion": null
}
```

> **Note**: This setting takes effect for **tokens newly issued after the change**. Tokens obtained before the change (clients such as MSAL cache them by default for 60–90 minutes) keep their original version, so in §4 be sure to obtain a fresh token.

### 2. Configure the plugin to accept v1.0 tokens

The `aud` claim of a v1.0 token is not the bare GUID but the **App ID URI form** (`api://<MIDDLE_TIER_ID>`). Change `DECK_AUDIENCE` in `.env` to the v1.0 value.

```bash
# .env (the table in Guide 03 §5 sets the bare GUID for v2.0)
DECK_AUDIENCE=api://<MIDDLE_TIER_ID>
```

Enable `allow_v1_tokens: true`, which is commented out in the obo plugin configuration of `examples/kong.yaml`.

```yaml
          audiences:
            - ${{ env "DECK_AUDIENCE" }}
          allow_v1_tokens: true
```

Apply the changes to the gateway (`deck` reads the `DECK_*` environment variables, so run it in the same shell that sourced `.env`).

```bash
set -a; source .env; set +a
deck gateway diff examples/kong.yaml    # confirm the diff shows audiences and allow_v1_tokens
deck gateway sync examples/kong.yaml    # apply to Konnect (distributed to the DP within seconds)
```

### 3. Wiring check (using mock tokens only)

Access `/downstream` with no token, and with a dummy string that is not a real token, and confirm that the obo plugin returns 401. In both cases the plugin rejects the request before it reaches the upstream, so no request is sent to the downstream API.

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

### 4. Obtain the user's token (token A)

Using the device code flow, you can get it with just curl. The token request can stay on the v2.0 endpoint (`/oauth2/v2.0/...`) — no problem (the version of the issued token is determined solely by the manifest setting in §1, independent of the endpoint).

```bash
# ① Get a device code and show the sign-in instructions
set -a; source .env; set +a
DEVICE_RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/${DECK_TENANT_ID}/oauth2/v2.0/devicecode" \
  -d "client_id=${CLIENT_APP_ID}" \
  --data-urlencode "scope=api://${DECK_CLIENT_ID}/access_as_user")
echo "$DEVICE_RESPONSE" | jq -r .message
```

Open the displayed URL (`verification_uri`) in a browser, enter the code (`user_code`), and sign in.

```bash
# ② After signing in, obtain the token (token A)
TOKEN_A=$(curl -s -X POST "https://login.microsoftonline.com/${DECK_TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=$(echo "$DEVICE_RESPONSE" | jq -r .device_code)" \
  -d "client_id=${CLIENT_APP_ID}" | jq -r .access_token)
[ "$TOKEN_A" != "null" ] && echo "OK: obtained token A"
# OK: obtained token A
```

If you run ② before completing sign-in, you get an `authorization_pending` error and `TOKEN_A` becomes `null`. In that case, re-run only ② after signing in.

### 5. Confirm token A is in v1.0 format

Since this guide's verification assumes "the token that arrived is truly v1.0 format," decode and confirm it before attempting the exchange (token A is a token for your own app, so decoding locally is fine; do not paste it into external sites).

```bash
jwt decode "$TOKEN_A"
```

Items to check:

- `ver` is `"1.0"` (if it is `"2.0"`, the manifest change in §1 has not taken effect. Confirm it is saved and **obtain a fresh token**)
- `iss` is `https://sts.windows.net/<TENANT_ID>/` (with a trailing slash)
- `aud` is `api://<MIDDLE_TIER_ID>` (an exact match to the value set for `DECK_AUDIENCE` in §2)
- `scp` contains `access_as_user`

### 6. Verify the OBO exchange with a real token

Access `/downstream` with token A attached. When `DECK_DOWNSTREAM_URL` is `https://httpbin.org`, the `/anything` endpoint returns the received request as-is in JSON, so you can extract and inspect the `Authorization` header that reached the upstream (i.e. token B, which Kong swapped in).

```bash
TOKEN_B=$(curl -s -H "Authorization: Bearer ${TOKEN_A}" \
  "http://localhost:8000/downstream/anything" | jq -r '.headers.Authorization' | sed 's/^Bearer //')
[ "$TOKEN_B" != "null" ] && [ "$TOKEN_B" != "$TOKEN_A" ] && echo "OK: Authorization was swapped to token B"
# OK: Authorization was swapped to token B
```

> **Note**: This check sends token B (a real token) to the service at `DECK_DOWNSTREAM_URL` (a third-party service in the case of httpbin.org). Use it only when token B's audience is a test app with no real service; do not do this with tokens for real APIs such as Microsoft Graph.

### 7. Inspect the contents of token B

```bash
jwt decode "$TOKEN_B"
```

Items to check:

- `aud` is the downstream API (`api://<DOWNSTREAM_ID>`, or the bare GUID depending on the app configuration) (token A's `aud` was the middle-tier, so this shows it was swapped by the exchange)
- `scp` contains `Data.Read` (the scope name requested in `DECK_SCOPE`)

> **Note**: The format of token B (v1.0 / v2.0) is determined by the **downstream API's** `requestedAccessTokenVersion`. Even if the received token A is v1.0, the OBO exchange itself succeeds, and it is unrelated to token B's version.

## Summary of checkpoints

| Operation | Expected result |
|---|---|
| Access `/downstream` with no token | `401` + `WWW-Authenticate` header (does not reach the upstream) |
| Access `/downstream` with a dummy string | `401` + `WWW-Authenticate: Bearer error="invalid_token"` (does not reach the upstream) |
| Decode token A | `ver: "1.0"`, `iss: https://sts.windows.net/<TENANT_ID>/`, `aud: api://<MIDDLE_TIER_ID>` |
| Access `/downstream/anything` with token A | The echoed `Authorization` header is token B, which differs from token A |
| Decode token B | `aud` is the downstream API; `scp` contains `Data.Read` |

## Cleanup after verification

Accepting v1.0 is a compatibility configuration. After verification, if possible, revert to the standard setup (v2.0).

1. Set the middle-tier app manifest's `api.requestedAccessTokenVersion` back to `2` ([Guide 03 §3.2](03-entra-id-setup.md))
2. Set `DECK_AUDIENCE` in `.env` back to the bare GUID (`<MIDDLE_TIER_ID>`)
3. Comment out `allow_v1_tokens: true` in `examples/kong.yaml` again
4. Apply with `deck gateway sync examples/kong.yaml` and verify behavior with the procedure in [Guide 04 (v2.0)](04-obo-verification-v2.md)

## When it does not work

The plugin does not include failure details in the response, only in the debug log:

```bash
docker compose logs kong | grep "obo:"
```

Symptoms and remedies specific to v1.0 verification:

| Reason in the debug log | Cause and remedy |
|---|---|
| `v1.0 token rejected: set requestedAccessTokenVersion=2 ...` | `allow_v1_tokens` is still `false` (you forgot to uncomment it in `kong.yaml` in §2, or forgot `deck gateway sync`) |
| `audience mismatch` | `DECK_AUDIENCE` is still the bare GUID (a v1.0 `aud` is in the `api://` form; cross-check `aud` between §2 and §5) |
| `issuer mismatch` | token A is actually v2.0 format (e.g. a cached token obtained before the change in §1). Check `ver` in §5 and obtain a fresh token |
| (a 502 is returned) | Fetching the v1.0 OpenID metadata failed. With `allow_v1_tokens: true`, a failure to fetch the v1.0 metadata is treated as an overall failure (fail-close), so check the DP's connectivity to `login.microsoftonline.com` |

For reasons other than the above, review the relevant settings in [Guide 03](03-entra-id-setup.md) and the values in `.env` (re-run `deck gateway sync` after changes).
