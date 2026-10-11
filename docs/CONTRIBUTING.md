# Contributing to Keystone-MCP

## Repository hygiene

- Pull requests use the [PR template](../.github/pull_request_template.md).
- Bugs and features: [issue templates](../.github/ISSUE_TEMPLATE/) (security issues go through [SECURITY.md](../SECURITY.md), not public issues).
- Dependency updates: [Dependabot](../.github/dependabot.yml) opens weekly PRs for GitHub Actions and Python (`uv` ecosystem, `uv.lock`). See "Dependencies" below.
- Default reviewers: [CODEOWNERS](../.github/CODEOWNERS) (uncomment an owner line after creating `@keystone-codes/maintainers` in the org).

## Setup

Requires Python 3.11+ and Redis (used by the OAuth session store, the
login-pending store, and several RBAC/users-directory tests).

```bash
# with uv (recommended)
uv sync --extra dev

# or with plain pip
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Start Redis for the tests that need it:

```bash
docker run -d -p 6379:6379 redis:7
export KEYSTONE_MCP_REDIS_URL=redis://localhost:6379/0
```

## Dependencies

Dependabot runs weekly on the `uv` ecosystem and only touches `uv.lock`
(`versioning-strategy: lockfile-only`); it does not raise the lower bounds in
`pyproject.toml`, since those also constrain whoever installs this package
elsewhere. Minor and patch updates land together in one grouped PR; major
updates (other than `fastmcp`) get their own PR. `fastmcp` major updates are
ignored for the whole 0.4.x line — we stay on `fastmcp==3.4.4`. To update a
dependency by hand: `uv lock --upgrade-package <name>`.

## Running the tests

```bash
pytest -q
# or, with uv:
uv run pytest -q
```

Tests marked `integration` are optional, live-service tests that skip
themselves when their environment prerequisites are not present — you do not
need external services beyond Redis for the default run. The tests in
`tests/integration/` need `bash` and a reachable Redis (`KEYSTONE_MCP_REDIS_URL`);
they skip themselves when either is missing.

The users-directory tests that exercise PostgreSQL (`tests/test_users_migrations.py`,
`tests/test_users_domain.py`, `tests/test_users_concurrency.py`,
`tests/integration/test_users_admin_local_smoke.py`) are parametrized over
SQLite and PostgreSQL; the PostgreSQL cases skip themselves when
`KEYSTONE_TEST_POSTGRES_URL` is not set, so PostgreSQL is optional locally too:

```bash
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine
export KEYSTONE_TEST_POSTGRES_URL=postgresql+psycopg://postgres:postgres@localhost:5432/postgres
```

In CI, a `postgres:16-alpine` service is always available and
`KEYSTONE_TEST_POSTGRES_URL` is always set, so those cases are required there,
not skipped (`tests/test_users_migrations.py::test_postgres_is_configured_in_ci`
fails the build if they would silently skip).

CI runs the suite on Python 3.11, 3.12 and 3.13.

## Security checks

CI runs a dependency audit (`uv audit`, OSV database) on every pull request
and weekly, and a container image scan (Trivy) on every pull request. The
dependency audit is blocking; the image scan is informational only (it
reports Debian base-image CVEs that may have no fix yet) and does not block
the pull request. See [`SECURITY.md`](../SECURITY.md).

To run the same checks locally:

```bash
uv audit --frozen
```

```bash
docker build -t keystone-mcp:scan .
trivy image --severity CRITICAL,HIGH --ignore-unfixed keystone-mcp:scan
```

## Before opening a pull request

- Keep the test suite green: `pytest -q`.
- `uv run pytest tests/test_doc_links.py` checks every relative link and
  heading anchor in the Markdown docs.
- If you touch `src/keystone_mcp/config.py`, update
  [`.env.example`](../.env.example) and the configuration table in
  [`environment.md`](environment.md) to match — every `KEYSTONE_MCP_*` variable
  should appear in both. This is enforced by `tests/test_env_docs_sync.py`.
- If you change the RBAC policy file format or the built-in catalog, update
  [`rbac-policy-format.md`](rbac-policy-format.md) and the examples
  under [`examples/`](../examples/) accordingly.
- Keep commit messages and PR descriptions focused on behavior, not on
  internal ticket references — this is a public repository.
- Describe what changed and why in the PR description; link any relevant
  discussion or issue.

## Commit style

Short, imperative subject line (`fix: ...`, `feat: ...`, `docs: ...`,
`refactor: ...`, `test: ...`, `chore: ...`), optionally followed by a body
explaining the reasoning when it is not obvious from the diff.

## Releasing

The version is recorded in three places, and a tag push refuses to publish an
image unless all three (plus the tag itself) agree
(`scripts/check_version.py`, run as the `version-gate` job in
[`release.yml`](../.github/workflows/release.yml)). Before tagging a release:

1. Bump the version in `pyproject.toml` (`[project].version`) and in
   `src/keystone_mcp/__init__.py` (`__version__`).
2. Rename the `CHANGELOG.md` `[Unreleased]` heading to
   `[X.Y.Z] - YYYY-MM-DD` and add a fresh empty `[Unreleased]` heading above
   it for the next cycle.
3. Run `uv lock` so the lockfile matches `pyproject.toml`.
4. Run `uv run python scripts/check_version.py --tag vX.Y.Z` locally before
   pushing the tag; it fails with a clear message if anything is out of
   sync. Pre-release tags (`vX.Y.Z-rc1`) are not supported.

Once the tag is pushed, the `release.yml` workflow (`version-gate` →
`test` → `publish` → `github-release`) builds the image for both
`linux/amd64` and `linux/arm64`, starts the `linux/amd64` build against Redis
and checks it over HTTP (`scripts/smoke_image.sh`: `/healthz`, `/readyz`,
the container `HEALTHCHECK` status, and the non-root uid) before publishing
anything, pushes both platforms to GHCR, and creates a GitHub Release whose
notes are the matching `CHANGELOG.md` section
(`scripts/extract_changelog.py`).
