# Run Keystone-MCP on Kubernetes (example)

This is an example, not a supported Helm chart. Read
[production-docker.md](production-docker.md) first — every setting below is
the same, only the packaging differs.

## What the example contains

`examples/kubernetes/`:

| File | What it does |
|---|---|
| `kustomization.yaml` | Lists the applied resources, in the `keystone` namespace. |
| `namespace.yaml` | Creates the `keystone` namespace. |
| `configmap.yaml` | `rbac-policy.yaml` and `upstreams.yaml`, same content as [`examples/production/`](../../examples/production/). |
| `deployment.yaml` | Two replicas of the pinned `0.4.0` image, probes, resource limits. |
| `service.yaml` | ClusterIP on port 8080. |
| `secret.example.yaml` | Template for the Secret below — not applied by `kustomization.yaml`. |
| `ingress.example.yaml` | ingress-nginx example with TLS — not applied by `kustomization.yaml`. |
| `networkpolicy.example.yaml` | Restricts an upstream's ingress to Keystone's own pods — not applied by `kustomization.yaml`. See [Protecting an upstream from pod-to-pod spoofing](#protecting-an-upstream-from-pod-to-pod-spoofing) below. |

Redis and Postgres are not part of this example: use your managed Redis and
Postgres, the same way a managed database is used in any other cluster
workload.

## Before you apply

1. A reachable Redis and a reachable Postgres (production requires Postgres
   for the users directory; see [environment.md](../environment.md#deployment-profile)).
2. A Google OAuth client — [google-oauth.md](../google-oauth.md).
3. The Secret `deployment.yaml` reads through `envFrom`:

   ```bash
   kubectl create secret generic keystone-secrets -n keystone \
     --from-literal=KEYSTONE_MCP_GOOGLE_CLIENT_SECRET=... \
     --from-literal=KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT="$(openssl rand -hex 32)" \
     --from-literal=KEYSTONE_MCP_REDIS_URL='redis://:<password>@<your-redis-host>:6379/0' \
     --from-literal=KEYSTONE_MCP_USERS_DB_URL='postgresql+psycopg://keystone:<password>@<your-postgres-host>:5432/keystone'
   ```

   `secret.example.yaml` shows the same four keys with placeholder values, for
   reference only — never apply it as written.
4. Edit `deployment.yaml`'s plain (non-secret) `env` block: `KEYSTONE_MCP_BASE_URL`,
   `KEYSTONE_MCP_GOOGLE_CLIENT_ID`, `KEYSTONE_MCP_SUPERADMIN_EMAIL`, and
   `FORWARDED_ALLOW_IPS` (see below).

## Apply

```bash
kubectl apply -k examples/kubernetes/
kubectl -n keystone get pods -w
```

Once both pods are `Ready`, point your ingress or gateway at the `keystone`
Service (see `ingress.example.yaml` for one way to do that) and sign in with
the account in `KEYSTONE_MCP_SUPERADMIN_EMAIL`.

## Probes

`livenessProbe` polls `/healthz`: process up, nothing checked. A hang
restarts the pod, nothing more.

`readinessProbe` polls `/readyz`: Redis answers, the RBAC policy loaded, and
the built-in users directory answers. A pod that fails `/readyz` is pulled
out of the Service's endpoints, not restarted — it rejoins once the
dependency recovers. (An external HTTP users directory, if your fork uses
one, is not part of this check — see [observability-logging.md](../observability-logging.md#readiness).)

## Two or more replicas

`deployment.yaml` sets `replicas: 2`. What that changes:

- Some state is shared in Redis across every pod (OAuth clients and tokens,
  pending logins, the users-directory revision marker); some lives in each
  pod's own process (the tool-call throttle, the login/registration IP
  throttle, the users-directory allow/deny cache) — a person's effective
  rate limit multiplies by the replica count. Full table:
  [environment.md#more-than-one-replica](../environment.md#more-than-one-replica).
- The users directory must be Postgres: SQLite is one file per pod and roles
  drift apart between replicas (the production profile already refuses
  SQLite; this is the same rule, not a Kubernetes-specific one).
- Users-directory migrations take a Postgres advisory lock, so several pods
  starting at once do not race each other.
- The RBAC policy file is re-read on its own refresh interval per pod — a
  policy change reaches every pod within that interval, not instantly.
- Policy tools are read-only with a ConfigMap mount; set
  `KEYSTONE_MCP_POLICY_TOOLS=read-only` (or `off`) or mount the policy from
  a writable PVC if agents should mutate it. See [policy-admin.md](../policy-admin.md).
- Behind an ingress controller, set `FORWARDED_ALLOW_IPS` (a plain
  uvicorn/environment variable, no `KEYSTONE_MCP_` prefix) to your ingress
  controller's pod network, or the login rate limiter sees the ingress pod's
  address for every caller instead of the real client:
  [environment.md#behind-a-reverse-proxy](../environment.md#behind-a-reverse-proxy).

## Metrics

`/metrics` is off by default (`KEYSTONE_MCP_METRICS_ENABLED`). If you turn
it on, a scrape must pass two checks: its source address must be in
`KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS` (default loopback only — add your
Prometheus pod network), and its `Host` must be allowed. Unlike `/healthz`
and `/readyz`, `/metrics` is not exempt from the Host check, and by default
only `KEYSTONE_MCP_BASE_URL`'s host is allowed, so a scrape by pod IP (pod
or endpoints discovery) or by Service name is refused with `421`. Scrape a
fixed name and add it to `KEYSTONE_MCP_ALLOWED_HOSTS` (e.g.
`keystone.keystone.svc.cluster.local:8080`); note that a scrape through the
Service reaches a different replica each time. Pod IPs cannot be listed in
advance.

## Protecting an upstream from pod-to-pod spoofing

`configmap.yaml`'s `upstreams.yaml` tells you to run your own service as a
plain `ClusterIP` Service with no further exposure. `ClusterIP` keeps the
upstream off the public internet, but it does **not** stop any other pod in
the same cluster from reaching it — and Keystone-MCP's only proof of who is
calling, by default, is the `X-Author-Email` header it sends on every
proxied call (see [connecting-services.md](../connecting-services.md)). Any
pod that can reach your upstream's Service can send that same header and
impersonate any user; Keystone-MCP's own RBAC enforcement runs in front of
*Keystone*, not in front of your upstream.

Two independent mitigations, either one closing a different half of the gap:

- **`NetworkPolicy`** — restrict which pods may even open a connection to the
  upstream, to Keystone's own pods (`app: keystone`). See
  `networkpolicy.example.yaml` (not applied by `kustomization.yaml`; adapt
  `podSelector` and apply it next to your upstream). Requires a CNI that
  enforces `NetworkPolicy` (Calico, Cilium, etc.) — some cluster network
  plugins silently ignore it.
- **`auth.bearer_env`** — have the upstream require a bearer token that only
  Keystone-MCP holds, in a registry entry's `auth.bearer_env` (an environment
  variable named `KEYSTONE_MCP_UPSTREAM_<NAMESPACE>_TOKEN` by convention —
  see [connecting-services.md](../connecting-services.md#authenticating-keystone-mcp-to-your-service)
  and [environment.md](../environment.md)). This proves the call came from
  Keystone-MCP regardless of which pod it came from; it does not by itself
  stop another pod from reaching the upstream's port at all.

A `NetworkPolicy` stops the connection; `auth.bearer_env` makes a connection
that does happen provably not Keystone-MCP's. Prefer both together — a
`NetworkPolicy` with no enforcing CNI, or a cluster policy change later that
relaxes it, still leaves `auth.bearer_env` standing.

## What is not covered

- **Helm** — no chart, no templating; copy and edit the plain YAML instead.
- **Autoscaling** — no `HorizontalPodAutoscaler`; add your own if you need one.
- **NetworkPolicy** for Keystone's own pods — nothing here restricts traffic
  *into* Keystone itself (only the example above, which protects an
  *upstream*); add policies that fit your cluster's network model.
