## Summary

<!-- What changed and why? Focus on behavior, not internal ticket IDs. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] Documentation only
- [ ] Tests / CI / tooling only

## Checklist

- [ ] `pytest -q` passes locally (or `uv run pytest -q`)
- [ ] If `src/keystone_mcp/config.py` changed: [`.env.example`](.env.example) and [`docs/environment.md`](docs/environment.md) are updated
- [ ] If RBAC policy format or built-in catalog changed: [`docs/rbac-policy-format.md`](docs/rbac-policy-format.md) and [`examples/`](examples/) are updated
- [ ] No secrets, credentials, or customer-specific data in the diff
- [ ] Linked issue or discussion (if applicable)

## Test plan

<!-- How did you verify this? Steps a reviewer can follow. -->
