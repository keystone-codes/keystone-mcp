# keystone-mcp Helm chart

Installs [Keystone-MCP](https://github.com/keystone-codes/keystone-mcp) on Kubernetes with ConfigMap-backed policy, upstream registry, and sign-in providers, credentials from a Secret, and optional Ingress, HPA, PodDisruptionBudget, NetworkPolicy, and Prometheus ServiceMonitor.

## Install

```bash
helm install keystone ./charts/keystone-mcp -f my-values.yaml
```

## Required values

| Value | Meaning |
|---|---|
| `baseUrl` | Public URL (`KEYSTONE_MCP_BASE_URL`) |
| `existingSecret` | Secret with `KEYSTONE_MCP_REDIS_URL`, `KEYSTONE_MCP_USERS_DB_URL`, `KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT`, and provider/upstream secrets |

Alternatively set `secret.create: true` and `secret.values` for demo/kind only.

## Common options

| Value | Default | Notes |
|---|---|---|
| `profile` | `production` | `local` for kind demos |
| `replicaCount` | `2` | Use Postgres for multiple replicas |
| `rbac.policyTools` | `read-only` | `full` needs `rbac.existingPolicyClaim` (RWX PVC) |
| `secretsAsFiles` | `false` | Mount Secret at `/run/secrets/keystone` |
| `ingress.enabled` | `false` | `ingress.host` must match `baseUrl` host |
| `autoscaling.enabled` | `false` | HPA v2 on CPU |
| `networkPolicy.enabled` | `false` | Restrict upstream ingress to Keystone pods |
| `redis.enabled` / `postgresql.enabled` | `false` | Demo only; use managed services in production |

See `values.yaml` for the full list.
