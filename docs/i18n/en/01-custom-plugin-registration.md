# Guide 01: Registering the custom plugin with Konnect

[日本語](../../01-custom-plugin-registration.md) | **English**

In Konnect hybrid mode, unless you register the obo plugin's **schema** with the Control Plane (CP), the CP cannot distribute the plugin configuration to the Data Plane (DP). (Installing the plugin itself onto the DP is done in [Guide 02](02-data-plane-build.md).)

## Prerequisites

- A Konnect account and a Control Plane already created
- Tools: `curl` / `jq`
- A Konnect personal access token (issue one on the [Konnect Personal Access Tokens page](https://cloud.konghq.com/global/account/tokens))

## Steps

### 1. Set environment variables

```bash
cp .env.example .env
```

Fill in the following two values in `.env` (the other variables are used in later guides):

```
DECK_KONNECT_TOKEN=<your Konnect personal access token>
DECK_KONNECT_CONTROL_PLANE_NAME=<target Control Plane name>
```

### 2. Register the schema

Load `.env`, then run the registration script.

```bash
set -a; source .env; set +a
scripts/upload-plugin-schema.sh upload
```

`scripts/upload-plugin-schema.sh` resolves the Control Plane ID from its name and registers `kong/plugins/obo/schema.lua` via the Konnect API (or updates it if already registered).

### 3. Verify the registration

```bash
scripts/upload-plugin-schema.sh verify
```

Registration is complete when it prints `OK: スキーマは登録されています` (the schema is registered).

## Alternative (registering via the UI)

1. Select the target Control Plane in [Gateway Manager](https://cloud.konghq.com/gateway-manager/)
2. **Plugins** → **New Plugin** → **Custom Plugins**
3. Upload `kong/plugins/obo/schema.lua`

## Notes

- If you use [mise](https://mise.jdx.dev/), you can also run `mise run schema:upload` / `mise run schema:verify` (mise loads `.env` automatically, so `source` is not needed)
- If you change `schema.lua`, re-run `scripts/upload-plugin-schema.sh upload` to update it
- After registration, `obo` appears in the Konnect Plugins list and can be configured on a Service / Route

Next: [Guide 02: Building and starting the Data Plane](02-data-plane-build.md)
