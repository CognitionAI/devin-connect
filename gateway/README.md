# Devin Gateway

The gateway is a customer-deployed appliance that gives Devin sessions access
to customer-internal systems (SCM, artifact registries, internal APIs) without
per-resource network configuration on the customer side. It is an HTTP CONNECT
proxy with a default-deny allowlist, reached either through an outbound-only
TLS tunnel to a Devin-side edge (tunnel mode) or on a local listener that
Devin dials directly, e.g. through a PrivateLink interface endpoint (direct
mode). Customer destination TLS is
never terminated by the gateway or the edge; payloads are opaque L4 streams.

Binary subcommands:

```
gateway serve --config /etc/devin-gateway/config.yaml
gateway validate-config --config config.yaml   # strict config validation
gateway doctor --config config.yaml [--resolve host]...  # JSON diagnostic summary
```

The container image is a static musl binary in a `FROM scratch` image
(Dockerfile target `gateway`), running as UID 65532 with tini as
PID 1. Mount the config at `/etc/devin-gateway/config.yaml` and, in tunnel
mode, the token file wherever `tunnel.auth_token_file` points.

## Deployment model

The gateway runs on the customer side and opens an outbound TLS connection to a
Devin-operated edge; the edge forwards Devin-side connections to the gateway
over that tunnel, and the gateway dials the destination only if a route allows
it. In direct mode there is no tunnel or token: the gateway serves HTTP CONNECT
on `listen`, and Devin dials that address, for example via an interface
endpoint to an endpoint service in front of the gateway. Routes are enforced on the gateway _and_ on the Devin side, so a
config-only change on one side cannot widen access. Per-session identity is
not part of this layer; connection audit logs carry the destination, matched
route, and client address. The enrollment token is never logged.

## Gateway config template

```yaml
schema_version: 1

# Admin listener (/healthz, /readyz, /metrics).
admin_listen: 127.0.0.1:9090

# Direct mode only (no `tunnel` stanza): the local HTTP CONNECT listener.
# Required without a tunnel, rejected with one — in tunnel mode CONNECT
# requests are served solely over the tunnel so the gateway host exposes no
# proxy port.
# listen: 0.0.0.0:8443

# Once one side of a connection has finished sending, close the connection
# when the other side stays silent for this long (default 5m). A peer that
# never closes would otherwise hold its sockets open forever. `0s` disables.
# half_close_timeout: 5m

# Customer DNS for resolving route targets (system resolver if omitted).
dns:
  nameservers: ["10.0.0.2:53"]
  timeout: 5s

# Default-deny allowlist. Hostname patterns support `*` wildcards; rules
# also accept ipv4/ipv6 CIDRs. Omitted ports means any port.
routes:
  - name: scm
    rules:
      - hostname: "git.corp.example"
      - hostname: "*.artifacts.corp.example"
    ports: [443]
  - name: internal-api
    rules:
      - hostname: "api.corp.example"
    ports: [443]

# Outbound tunnel to the Devin-side edge. Omit for direct (local-listener)
# mode and set `listen` instead. Tenant enrollment is authenticated by the token.
tunnel:
  endpoint: acme.gateway.devinenterprise.com:443
  gateway_id: acme-gw-1
  # Enrollment token, one line; re-read on every connection attempt so it
  # can be rotated without a restart.
  auth_token_file: /etc/devin-gateway/tunnel-token
  # carrier: websocket   # default; use `direct` to disable WebSocket framing.
  # ca_file: corp-ca.pem # only if a corporate TLS-inspection proxy re-signs
  #                      # the edge connection.
  # egress_proxy:        # customer egress HTTP CONNECT proxy, if required.
  #   addr: proxy.corp.example:3128
  connection_pool:
    size: 4 # 1..=16; the only reloadable tunnel field
    max_streams_per_connection: 512 # 2..=2048
```

Config is polled every 5s and hot-reloaded; a config that fails validation is
rejected as a whole and the previous one stays active.

## Token rotation

- **Enrollment token** (gateway→edge): write the new token issued by Devin to
  `auth_token_file`; the gateway picks it up on the next connection attempt,
  no restart. Old and new tokens overlap until the old one is revoked.
