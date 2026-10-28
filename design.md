# tunnelrs — design

A connector next to a backend dials out to a server over iroh, announces the hostnames it serves, and the server forwards visitor traffic back over that session. Backends need no inbound ports and no shared secrets.

- **Goal:** expose HTTP and TLS services from private networks with key-based identity and runtime approval.
- **Shape:** the server is never the edge. Something in front of it (an ingress controller, a reverse proxy) sends it traffic; on k8s, the k8s-operator declares the routing objects for that controller.
- **Non-goals for v1:** server HA, raw non-TLS TCP, certificate management, embedding as a library, PROXY protocol.

```
visitor ──> edge (ingress controller / proxy) ──> server  <══ iroh session ══  connector ──> backend
                     ^                              │                           (dials out)
                     └── routing objects ── k8s-operator (watches routes)
```

## Terminology

| Component | What it is |
| --- | --- |
| server | Hub; holds grants and routes, accepts sessions and forwarded visitor traffic |
| connector | Process next to the backend; dials the server, announces, forwards data streams |
| backend | The app being exposed (`localhost:8080`, a k8s Service) |
| k8s-operator | Watches routes on the server, creates routing objects for the cluster's controller |
| ctl | Admin CLI: approve, deny, revoke, list |
| visitor | Whoever connects to the public side |

| Concept | Meaning |
| --- | --- |
| connector ID | The connector's public key (iroh EndpointId) |
| session | One live QUIC connection between a connector and the server |
| control stream | Long-lived stream in a session for announcements and route status |
| data stream | One stream per forwarded connection, opened by the server |
| exposure | Connector-side config entry: hostname, backend, tls mode, meta |
| announcement | The full set of exposures a connector claims (without backend addresses) |
| route | A hostname the server forwards to one or more connectors |
| connector pool | All connectors currently serving the same route |
| grant | Connector ID + allowed hostname patterns (+ optionally allowed tls modes) |
| enrollment | Lifecycle of a connector ID: pending, approved, denied, revoked |
| route status | Per hostname: accepted, pending, denied, conflict |
| meta | Opaque string map per exposure, passed through to the k8s-operator |

## Identity, enrollment and grants

1. On first start the connector generates a key and persists it; the public half is its connector ID.
2. The connector is configured with the server's public ID and how to reach it. Nothing secret is distributed.
3. An unknown connector ID that announces becomes `pending`; the server stores the hostnames it asked for.
4. An admin approves with `ctl approve <id> --hosts '*.foo.example.com'`, creating a grant.
5. Announcements matching the grant go live; everything else gets a status with a reason.

- Grants live in server-owned runtime state (sqlite via sqlx, compile-time checked queries), not declarative config.
- Grant patterns: `*` matches exactly one label (`*.foo.example.com` matches `a.foo.example.com`, not `a.b.foo.example.com` or the apex). A grant holds multiple patterns.
- A grant can optionally restrict tls modes.
- A pending connector keeps its session open; approval re-evaluates its current announcement live.
- Deny closes the session. Denied and revoked IDs are rejected at handshake until an explicit `ctl approve`; they never return to `pending` on their own.
- Revoking closes the connector's session immediately.
- Admin (ctl) and operator keys are listed in the server's config file and authenticate the same way. Each key has a role: `admin` (all commands) or `watcher` (route watch stream only; the operator).

## Protocols (ALPNs)

| ALPN | Who dials | Purpose |
| --- | --- | --- |
| `tunnelrs/connector/1` | connector | session: control stream + server-opened data streams |
| `tunnelrs/admin/1` | ctl, k8s-operator | admin commands and the route watch stream |

Version lives in the ALPN. After the handshake the dialing side opens one bi stream that carries remoc (its default postbag codec) for all typed traffic. Data streams are raw iroh streams opened by the server on the same connection, outside remoc, so visitor traffic keeps per-stream flow control and never queues behind other streams.

- The protocol handler checks the peer's key and hands out only the remoc rtc client for its role: `ConnectorClient`, `AdminClient` or `WatchClient`. A role can't call what it doesn't hold.
- Connector: `announce(exposures)` is an rtc call; per-hostname status is an `ObservableHashMap<Hostname, RouteStatus>` the connector mirrors, so approvals show up live.
- Watch: `subscribe()` returns `(db_id, HashMapSubscription<Hostname, RouteView>)`. `RouteView` holds tls, meta, live/offline state and pool members; removal means withdrawn. On `Lagged` the subscriber subscribes again.

### Server state

One control-plane task serialises every mutation (announce, session up/down, approve, deny, revoke, forget, expiry): write to sqlite (sqlx), then update two in-memory structures in step:

- the `ObservableHashMap<Hostname, RouteView>` for watchers (serialisable views only);
- the forwarding table (`RwLock`/`ArcSwap` of `Hostname -> Pool { sessions, rr }`), which the `http` and `tls` listeners read. Forwarding never goes through the remoc map.

`db_id` is a random ID created with the database. The operator stores it as an annotation on every object it manages; when it changes, missing routes count as offline (grace period applies), never as withdrawn.

## Connector lifecycle

| Step | What happens |
| --- | --- |
| Start | Load key and exposures from local config |
| Connect | Dial the server's ID: a session |
| Announce | Send the full exposure set on the control stream |
| Status | Server replies per hostname: accepted, pending, denied or conflict |
| Serve | Accept data streams, read the header, dial the backend, forward |
| Reload | Re-announce the full set |
| Drop | Session ends; the server removes this connector from its pools |

Announcement entry per exposure:

| Field | Values |
| --- | --- |
| hostname | `app.example.com` |
| tls | `terminate` or `passthrough` |
| meta | string map, e.g. `k8s/auth: authentik` |

- Backend addresses never leave the connector.
- The server persists each connector's last announcement in sqlite; every change re-sends the full set. A route is *live* while a session serving it is up, *offline* after the last session drops, and *withdrawn* when a re-announce omits it, on revoke, on `ctl forget`, or after 24h offline. All states survive server restarts, and the watch stream reports them distinctly.
- Reload triggers: SIGHUP and a change to the config file.
- Data streams are byte pipes: the server writes a header (hostname), the connector dials the backend over TCP and replies with a 1-byte ack (`ok` or an error code), then copies bytes. A failed ack lets the server retry another pool member or answer 502. The connector never parses HTTP, so terminate backends speak plain HTTP.

## Server: listeners and TLS modes

The server never holds 443 and never touches certificates.

| Listener | Exposure | Routes by | Used for |
| --- | --- | --- | --- |
| `http` (TCP) | internal | `Host` header, per request | terminate routes |
| `tls` (TCP) | internal | SNI peek, raw bytes onward | passthrough routes |
| iroh endpoint | see Connectivity | ALPN + node ID | sessions, admin |

| | terminate | passthrough |
| --- | --- | --- |
| TLS ends at | the edge | the backend |
| Server sees | plain HTTP | encrypted bytes |
| Visitor IP to backend | `X-Forwarded-*` from the edge passed on unchanged; the server adds none | not carried |
| No live connector | 503 | close the connection |
| Unknown hostname, or a route of the other mode | 404 | close the connection |
| Port 80 | handled by the edge | not carried |

### HTTP listener must route per request

All routing objects point at the same server Service, so the edge pools upstream connections to the server and **one keep-alive connection can carry requests for different hosts** (and the edge may speak h2c). Therefore:

- The `http` listener is a real HTTP server (hyper): route each request by `Host`, not each TCP connection.
- Per connector session, the server keeps an HTTP/1.1 client over data streams (one data stream = one HTTP/1.1 connection to the backend) and forwards requests on it. The edge may still speak h2c to the server. h2c towards the backend can later become a per-exposure announced flag.
- Upgrades (WebSocket, `Connection: upgrade`) are supported: after the 101, bytes are piped.

The `tls` listener is connection-level: peek the ClientHello, read SNI, open a data stream, pipe bytes.

- Certificates for passthrough routes are the backend's concern.
- Pool balancing: round-robin over live sessions. A pool can hold several sessions of one connector ID (replicas sharing a key) as well as sessions from different granted connector IDs.

## Connectivity: direct UDP or relay

The server needs no inbound port: if direct UDP is unreachable, both sides dial out to an iroh relay and hole punching upgrades to a direct path when possible. Support both.

| Option | Server exposure | Trade-off |
| --- | --- | --- |
| Inbound UDP on server | one UDP port | always direct, no relay dependency |
| Own relay (`iroh-relay`) | none | relay needs a public IP + DNS name; relayed when hole punching fails |
| n0 public relays | none | rate-limited, development only |

- Server config: optional bind/advertised address(es) + relay URL list.
- Connector config: server ID + relay URL(s) + optional direct address.

## Metadata

- Opaque string map per exposure; the server stores it with the route and exposes it in the watch stream, never interprets it.
- Namespaced keys (`k8s/auth`). Size-limited (4 KiB per exposure).
- Pool rule: all connectors in a pool must announce byte-identical meta and tls mode; a mismatch puts the newcomer in `conflict`. An offline pool (persisted announcement, no live session) still holds the hostname, so a restart cannot flip a route's meta.
- Meta only selects operator presets; values never go into annotations or templates.

## k8s-operator

| Piece | Role |
| --- | --- |
| Base template per mode | Resource kind + skeleton. Built in: `Ingress`, Traefik `IngressRoute` / `IngressRouteTCP`, Gateway API `TLSRoute`; users can add or override templates in operator config. Variables: host, server service and port, route name |
| Presets | Named patches, selected via a meta key/value match; each declares which modes it applies to |
| Policy | Per hostname pattern and/or connector ID: allowed presets and forced presets |

A preset patch is a map of `path: value` sets. Paths are dotted; `[*]` applies to every element of an array, `[n]` to one element.

```yaml
modes:
  terminate:   { template: traefik-ingressroute }
  passthrough: { template: traefik-ingressroutetcp }
presets:
  auth-authentik:
    modes: [terminate]
    match: { k8s/auth: authentik }
    patch:
      spec.routes[*].middlewares: [{ name: authentik-forward-auth }]
policy:
  - hosts: "*.internal.example.com"
    force: [auth-authentik]
```

- Input: the remoc route subscription over `tunnelrs/admin/1`, authenticated by the operator's key; reconciliation is level-triggered on the mirror.
- Presets reference existing objects (e.g. a Middleware); the operator doesn't create them.
- A preset on an unsupported mode is rejected and reported as an event.
- Objects follow grant + route, not session: delete only on withdraw, revoke, or after a route has been offline for the grace period (default 24h). The operator records the last time it saw the route live as an annotation on the object, so the grace period survives operator restarts.
- An empty route table after a server restart is never "delete everything".
- Everything it creates is labelled; it only touches its own objects.

## Simple mode

Same server, no operator. Traffic is assumed to reach the `http` and `tls` listeners by whatever means the user sets up; tunnelrs generates no edge config.

## ctl

| Command | Does |
| --- | --- |
| `list` | Connectors, enrollment state, sessions, routes |
| `approve` / `deny` | Decide a pending connector. `approve` without `--hosts` grants exactly the hostnames it requested; approving again replaces the grant's patterns |
| `revoke` | Remove a grant and close the session |
| `routes` | Status per hostname and pool size |
| `forget <hostname>` | Drop a stored offline route so its hostname is free again |

## Defaults

| Decision | Default |
| --- | --- |
| Pool with mismatched meta or tls mode | Byte-identical required, else `conflict` |
| Pool membership | Multiple sessions per connector ID and multiple connector IDs, same meta and tls mode |
| Pool balancing | Round-robin over live sessions |
| Grant pattern `*` | Exactly one DNS label |
| Pending connector | Session stays open; approval applies live |
| Denied / revoked ID | Rejected at handshake until approved again |
| Admin key roles | `admin` or `watcher` |
| Connector data path | Byte pipe to backend TCP |
| Operator on session drop | Keep objects; delete on withdraw, revoke, or 24h offline |
| Unknown hostname | 404 on `http`, close on `tls` |
| `X-Forwarded-*` | Passed on from the edge; none added |
| HTTP to backend | HTTP/1.1 |
| Connector reload | SIGHUP and config file change |
| Config format | TOML, loaded with `toml-file-refs` (`*_file` keys for secrets) |
| Conflict precedence | Existing pool wins, also when offline |
| Revoke | Close the session immediately |
| Offline route | Expires to withdrawn after 24h; `ctl forget` drops it immediately |
| Wire format | remoc (its default postbag codec) on one control stream; raw streams for data; version in ALPN |

## Code layout

Cargo workspace, one binary per component so the operator's kube dependencies stay out of the rest:

| Crate | Kind |
| --- | --- |
| `crates/proto` | lib: ALPNs, remoc rtc traits and shared types, data stream header |
| `crates/server` | bin `tunnelrs-server` |
| `crates/connector` | bin `tunnelrs-connector` |
| `crates/ctl` | bin `tunnelrs-ctl` |
| `crates/operator` | bin `tunnelrs-operator` |

v1 scope is everything in this document.

Out of scope for v1: server HA, raw non-TLS TCP, certificate management, embedding as a library, PROXY protocol.
