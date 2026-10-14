# Run Keystone-MCP on Kubernetes

Read [production-docker.md](production-docker.md) first — cluster settings match
that path; only the packaging differs.

## Install with Helm

```bash
helm install keystone ./charts/keystone-mcp -f my-values.yaml
```

**Required values:** `baseUrl` (`KEYSTONE_MCP_BASE_URL`) and either
`existingSecret` (name of a Secret you create) or `secret.create: true` with
`secret.values` for demo/kind only.

**Secret keys** (same as the kustomize example): `KEYSTONE_MCP_REDIS_URL`,
`KEYSTONE_MCP_USERS_DB_URL`, `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT`, plus any
`client_secret_env` names from your `loginProviders` file and upstream
`auth.bearer_env` tokens. Alternatively set `secretsAsFiles: true` to mount
the Secret under `/run/secrets/keystone` and use `KEYSTONE_MCP_*_FILE` (see
[environment.md#secrets-from-files](../environment.md#secrets-from-files)).

**Ingress and TLS:** set `ingress.enabled`, `ingress.className`,
`ingress.host` (must match the host in `baseUrl`), and `ingress.tls.secretName`.

**Several replicas:** use external or chart demo Postgres
(`postgresql.enabled` is demo-only); SQLite (`profile: local`) cannot run on
more than one pod.

**Policy from ConfigMap:** default `rbac.policyTools: read-only` so
`policy_*` mutations are refused when the policy file is read-only. For
`policy_*` writes, mount a ReadWriteMany PVC and set `rbac.existingPolicyClaim`
with `rbac.policyTools: full`.

**Upstream registry from ConfigMap:** kubelet refreshes mounted ConfigMap
files on the order of one minute after you edit the ConfigMap. Keystone picks
up the new registry on the next refresh tick after that, or immediately on
`SIGHUP` — no rolling restart of the Deployment is required.

Chart reference: [`charts/keystone-mcp/README.md`](../../charts/keystone-mcp/README.md).

## Without Helm (kustomize example)

Plain YAML under `examples/kubernetes/` — copy and edit; there is no
templating in this example.

### What the example contains

`examples/kubernetes/`:

| File | What it does |
|---|---|
| `kustomization.yaml` | Lists the applied resources, in the `keystone` namespace. |
| `namespace.yaml` | Creates the `keystone` namespace. |
| `configmap.yaml` | `rbac-policy.yaml`, `login-providers.yaml`, and `upstreams.yaml`, aligned with [`examples/production/`](../../examples/production/). |
| `pdb.yaml` | `PodDisruptionBudget` with `minAvailable: 1` during voluntary disruptions. |
| `deployment.yaml` | Two replicas of the pinned `0.5.0` image, probes, resource limits. |
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
2. A Google OAuth client — [google-oauth.md](../google-oauth.md). Sign-in is
   configured in the `login-providers.yaml` key inside `configmap.yaml` (same
   shape as [`examples/production/login-providers.yaml`](../../examples/production/login-providers.yaml));
   put the client secret in the Secret under the variable named in
   `client_secret_env` (`KEYSTONE_MCP_LOGIN_GOOGLE_SECRET` in this example).
3. The Secret `deployment.yaml` reads through `envFrom`:

   ```bash
   kubectl create secret generic keystone-secrets -n keystone \
     --from-literal=KEYSTONE_MCP_LOGIN_GOOGLE_SECRET=... \
     --from-literal=KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT="$(openssl rand -hex 32)" \
     --from-literal=KEYSTONE_MCP_REDIS_URL='redis://:<password>@<your-redis-host>:6379/0' \
     --from-literal=KEYSTONE_MCP_USERS_DB_URL='postgresql+psycopg://keystone:<password>@<your-postgres-host>:5432/keystone'
   ```

   `secret.example.yaml` shows the same four keys with placeholder values, for
   reference only — never apply it as written. Alternatively, mount each value
   as a file and set `KEYSTONE_MCP_<NAME>_FILE` to the mount path (see
   [environment.md#secrets-from-files](../environment.md#secrets-from-files)).
4. Edit `configmap.yaml`'s `login-providers.yaml` (`client_id`, optional
   `allowed_domain`) and `deployment.yaml`'s plain (non-secret) `env` block:
   `KEYSTONE_MCP_BASE_URL`, `KEYSTONE_MCP_SUPERADMIN_EMAIL`, and
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

`startupProbe` polls `/healthz` for up to 180 seconds (`periodSeconds: 5`,
`failureThreshold: 36`) while upstream discovery and the users directory
migrate. Until it succeeds, liveness and readiness probes do not run, so a
slow start does not trigger a restart loop.

`livenessProbe` polls `/healthz`: process up, nothing checked. A hang
restarts the pod, nothing more.

`readinessProbe` polls `/readyz`: Redis answers, the RBAC policy loaded, and
the built-in users directory answers. A pod that fails `/readyz` is pulled
out of the Service's endpoints, not restarted — it rejoins once the
dependency recovers. (An external HTTP users directory, if your fork uses
one, is not part of this check — see [observability-logging.md](../observability-logging.md#readiness).)

## Shutdown

`lifecycle.preStop` sleeps 5 seconds so the Service endpoints update before
SIGTERM. `terminationGracePeriodSeconds: 40` covers that sleep, the
25-second `KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS` in-flight request drain, and
a small margin. `pdb.yaml` keeps at least one pod available during voluntary
disruptions (node drain, cluster upgrade).

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
- The example sets `KEYSTONE_MCP_POLICY_TOOLS=read-only` because the policy
  ConfigMap is mounted read-only. Mutating `policy_*` tools need a writable
  mount (for example a PVC with the same file) and `KEYSTONE_MCP_POLICY_TOOLS=full`.
  See [policy-admin.md](../policy-admin.md).
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
and `/readyz`, `/metrics` is not exempt from the Host check entirely, but
it **does** accept a `Host` whose host part is a pod IP literal (for example
`10.1.2.3:8080`), so Prometheus can scrape each pod by IP without listing
every address in `KEYSTONE_MCP_ALLOWED_HOSTS`. Add the Prometheus pod CIDR to
`KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`. Example pod discovery:

```yaml
# prometheus.yml (fragment)
scrape_configs:
  - job_name: keystone-mcp
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: keystone-mcp
```

A scrape through a Service name still needs that name on the allowlist and
load-balances across replicas; per-pod scraping keeps counters separate.

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

- **Autoscaling in the kustomize example** — no `HorizontalPodAutoscaler`; use
  the Helm chart's `autoscaling.enabled` or add your own.
- **NetworkPolicy** for Keystone's own pods — nothing here restricts traffic
  *into* Keystone itself (only the example above, which protects an
  *upstream*); add policies that fit your cluster's network model.
