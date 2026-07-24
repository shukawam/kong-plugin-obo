# Guide 02: Building and starting the Data Plane

[日本語](../../02-data-plane-build.md) | **English**

Start a Kong Gateway with the obo plugin built in as a Konnect Data Plane (DP) using Docker Compose.

## Prerequisites

- Docker / Docker Compose v2
- [Guide 01](01-custom-plugin-registration.md) completed (schema registered with the CP)
- Local ports `8000` / `8100` / `3000` / `4317` / `4318` are free (if another Kong Gateway or container is using them, startup fails with a port conflict; check with `docker ps` and stop whatever is using them first)

## Steps

### 1. Place the DP connection details

From the connection details shown under [Gateway Manager](https://cloud.konghq.com/gateway-manager/) → target Control Plane → **Data Plane Nodes** → **New Data Plane Node**:

1. Save the **cluster certificate pair** to the following paths (`cluster-certs/` is gitignored; do not commit it):
   - `cluster-certs/cluster.crt`
   - `cluster-certs/cluster.key`
2. Record the prefix of the connection URL (the `<PREFIX>` part of `https://<PREFIX>.us.cp0.konghq.com`) in `.env`:

   ```
   PREFIX=<DP connection prefix>
   ```

### 2. Build and start

After editing `.env`, always reload it before starting. Docker Compose **gives priority to environment variables already exported in the shell over `.env`**, so if the stale value from the `source .env` in [Guide 01](01-custom-plugin-registration.md) (an empty `PREFIX`) remains in your shell, the container will start with it empty even though you filled it in `.env`.

```bash
set -a; source .env; set +a
docker compose up --build -d
```

- The `Dockerfile` builds an image that installs the obo plugin onto the `kong/kong-gateway` base image with `luarocks make`
- Plugin loading (`KONG_PLUGINS=bundled,obo`) is already configured in `compose.yaml`

### 3. Verify startup

```bash
docker compose ps          # kong should be healthy
```

Setup is complete once the node shows as **Connected** under **Data Plane Nodes** in [Gateway Manager](https://cloud.konghq.com/gateway-manager/).

## Notes

- If you change the plugin code (`kong/plugins/obo/`), rebuild with `docker compose up --build -d`
- `compose.yaml` also includes an observability stack (otel-lgtm)

Next: [Guide 03: Setting up Entra ID](03-entra-id-setup.md)
