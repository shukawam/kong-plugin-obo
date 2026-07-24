# Guide 04: Verifying OBO token exchange (v2.0 tokens, standard setup)

[日本語](../../04-obo-verification-v2.md) | **English**

Configure the obo plugin on a Kong Route and confirm that it can actually exchange a user's token for a downstream-API token.

This guide targets the standard setup (the middle-tier app has `requestedAccessTokenVersion: 2` and receives v2.0-format tokens; [Guide 03 §3.2](03-entra-id-setup.md)). To verify an environment where v1.0-format tokens arrive (`allow_v1_tokens: true`), use [Guide 04-v1: Verifying OBO token exchange (v1.0 tokens)](04-obo-verification-v1.md).

## Prerequisites

- [Guide 01](01-custom-plugin-registration.md) through [03](03-entra-id-setup.md) completed
- Tools: `curl` / `jq` / `deck` (the `jwt` command from [jwt-cli](https://github.com/mike-engel/jwt-cli) is handy for decoding token B)
- All variables in `.env` filled in (see the mapping in [Guide 03 §5](03-entra-id-setup.md))
- `DECK_DOWNSTREAM_URL` in `.env` set to the base URL of the downstream API that is token B's actual audience. If the downstream API registered in [Guide 03](03-entra-id-setup.md) is a test app with no real service, set the request-echo API `https://httpbin.org` (so you can inspect token B's contents in §4–5). To use Microsoft Graph as the downstream, set `https://graph.microsoft.com` (see "Notes")

## Steps

### 1. Sync the gateway configuration to Konnect

`examples/kong.yaml` defines a verification Service (upstream is `DECK_DOWNSTREAM_URL` in `.env`, i.e. the downstream API that is token B's canonical audience), a Route (`/downstream`), and the obo plugin configuration. The setting values are resolved from the `DECK_*` variables in `.env`.

Before syncing, confirm that `DECK_DOWNSTREAM_URL` starts with `https://`. HTTPS is required to prevent token B from being sent in the clear. This URL must also match the audience of `DECK_SCOPE` (token B's canonical destination).

```bash
set -a; source .env; set +a
[[ "$DECK_DOWNSTREAM_URL" == https://* ]] && echo OK || echo "NG: DECK_DOWNSTREAM_URL must start with https://"
# OK
```

```bash
deck gateway diff examples/kong.yaml    # review the diff to be applied
deck gateway sync examples/kong.yaml    # apply to Konnect (distributed to the DP within seconds)
```

deck reads the `DECK_*` environment variables loaded above, so run it in the same shell that sourced `.env`. If you use [mise](https://mise.jdx.dev/), you can also run `mise run gateway:diff` / `mise run gateway:sync` (mise loads `.env` automatically, so `source` is not needed).

Whenever you change a value in `.env`, be sure to re-run `deck gateway sync`.

### 2. Wiring check (using mock tokens only)

Access `/downstream` with no token, and with a dummy string that is not a real token, and confirm that the obo plugin returns 401. In both cases the plugin rejects the request before it reaches the upstream, so no request is sent to the downstream API. Getting a 401 is itself confirmation that "the plugin is in effect on the Route."

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

### 3. Obtain the user's token (token A)

Using the device code flow, you can get it with just curl.

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

### 4. Verify the OBO exchange with a real token

Access `/downstream` with token A attached. When `DECK_DOWNSTREAM_URL` is `https://httpbin.org`, the `/anything` endpoint returns the received request as-is in JSON, so you can extract and inspect the `Authorization` header that reached the upstream (i.e. token B, which Kong swapped in).

```bash
TOKEN_B=$(curl -s -H "Authorization: Bearer ${TOKEN_A}" \
  "http://localhost:8000/downstream/anything" | jq -r '.headers.Authorization' | sed 's/^Bearer //')
[ "$TOKEN_B" != "null" ] && [ "$TOKEN_B" != "$TOKEN_A" ] && echo "OK: Authorization was swapped to token B"
# OK: Authorization was swapped to token B
```

> **Note**: This check sends token B (a real token) to the service at `DECK_DOWNSTREAM_URL` (a third-party service in the case of httpbin.org). Use it only when token B's audience is a test app with no real service; do not do this with tokens for real APIs such as Microsoft Graph.

### 5. Inspect the contents of token B

Decode with the `jwt` command from [jwt-cli](https://github.com/mike-engel/jwt-cli) and check the claims of the exchanged token.

```bash
jwt decode "$TOKEN_B"
```

Items to check:

- `aud` is the downstream API (`api://<DOWNSTREAM_ID>`, or the bare GUID depending on the app configuration) (token A's `aud` was the middle-tier, so this shows it was swapped by the exchange)
- `scp` contains `Data.Read` (the scope name requested in `DECK_SCOPE`)

If you do not have the `jwt` command, you can also paste token B into the decoder at [jwt.io](https://jwt.io/) (on macOS, copy with `printf %s "$TOKEN_B" | pbcopy`). Decoding happens entirely in the browser, but only paste token B intended for a test app.

## Summary of checkpoints

| Operation | Expected result |
|---|---|
| Access `/downstream` with no token | `401` + `WWW-Authenticate` header (does not reach the upstream) |
| Access `/downstream` with a dummy string | `401` + `WWW-Authenticate: Bearer error="invalid_token"` (does not reach the upstream) |
| Access `/downstream/anything` with token A | The echoed `Authorization` header is token B, which differs from token A |
| Decode token B | `aud` is the downstream API; `scp` contains `Data.Read` |

## Notes: using Microsoft Graph as the downstream API

Set `.env` to `DECK_DOWNSTREAM_URL=https://graph.microsoft.com` and `DECK_SCOPE=https://graph.microsoft.com/user.read`. In addition, add the Microsoft Graph delegated permission `User.Read` to the middle-tier app's **API permissions** and grant admin consent (**Grant admin consent for \<tenant\>**). Graph has no echo endpoint, so instead of §4–5, verify with a successful profile fetch (`200`) (token B's contents are not inspected).

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  "http://localhost:8000/downstream/v1.0/me"
# 200
```

## When it does not work

The plugin does not include failure details in the response, only in the debug log:

```bash
docker compose logs kong | grep "obo:"
```

You will see `obo: unauthorized: <reason>` or `obo: token exchange failed: <Entra error>`, so depending on the reason, review the relevant settings in [Guide 03](03-entra-id-setup.md) and the values in `.env` (re-run `deck gateway sync` after changes).

If token exchange fails in a setup that uses Microsoft Graph as the downstream API, also check whether the middle-tier app has the Microsoft Graph delegated permission `User.Read` and admin consent (see "Notes").
