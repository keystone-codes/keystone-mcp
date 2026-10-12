# Keystone-MCP documentation

Pick the section that matches what you do; each link says what you will
find there, not just the file name.

## Start here

- [Run it on your machine](paths/local-compose.md) — three containers, one
  sign-in, a role change, in about 15 minutes
- [Deploy to production](paths/production-docker.md) — Docker, Postgres and
  TLS on your own domain
- [Kubernetes example](paths/kubernetes.md) — the same settings, packaged
  for a cluster (not a Helm chart)
- [What Keystone-MCP does](features.md) — every capability in depth, and
  what is still 0.5.0

## I build an agent application or a service behind Keystone-MCP

- [Connect an MCP client](clients.md) — Claude Code, Cursor, Claude Desktop
- [Connect your service](connecting-services.md) — the contract an upstream
  MCP service has to meet
- [How sections, discovery and the proxy work](facade.md)
- [Mount options, timeouts, schema patches, extending a fork](adding-routes.md)
- [Sample upstream service](../examples/hello-upstream/README.md)
- [contrib: reference code for forks](contrib/README.md), including the
  [reference adapters](contrib/adapters.md)

## I run Keystone-MCP

- [Production in four steps (overview)](quickstart.md)
- [Host install with systemd](deploy.md)
- [Every `KEYSTONE_MCP_*` setting](environment.md)
- [Before going live](production-checklist.md)
- [Sign-in providers (Google, OIDC)](login-providers.md)
- [Plugins (entry points)](plugins.md)
- [Google sign-in (legacy page)](google-oauth.md)
- [Logs](observability-logging.md)
- [Metrics and audit](observability-rbac.md)
- [Security model](security-model.md) — the three things that decide access

## I manage who has access

- [People and roles](users.md)
- [The `UserDirectory` protocol — writing your own directory](user-directory.md)
- [Policy file format](rbac-policy-format.md)
- [Change the policy from the agent](policy-admin.md)
- [Check a policy offline](rbac-catalog-registry.md)
- [Generated role matrix](rbac-role-matrix-per-tool.md)
- [Agent skill for user administration](../skills/keystone-user-admin/SKILL.md)
- [Agent skill for policy administration](../skills/keystone-policy-admin/SKILL.md)

## Project

- [Why things are the way they are](adr/README.md)
- [Changelog](../CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [Security reports](../SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
