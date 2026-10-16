# Contributing to Keystone-MCP

## Repository hygiene

- Pull requests use the [PR template](../.github/pull_request_template.md).
- Bugs and features: [issue templates](../.github/ISSUE_TEMPLATE/) (security issues go through [SECURITY.md](../SECURITY.md), not public issues).
- Dependency updates: [Dependabot](../.github/dependabot.yml) opens weekly PRs for GitHub Actions and Python (`uv` ecosystem, `uv.lock`). See "Dependencies" below.
- Default reviewers: [CODEOWNERS](../.github/CODEOWNERS) (uncomment an owner line after creating `@keystone-codes/maintainers` in the org).
- Do not reference internal task or audit IDs in code, tests or docs; explain the reason or link an ADR.

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
updates (other than `fastmcp` and `mcp`) get their own PR. Major upgrades of
`fastmcp` and `mcp` are ignored by Dependabot and done as planned work (we
currently run `fastmcp>=4.1,<5`, MCP SDK 2). Why: [ADR 0010](adr/0010-fastmcp-major-version.md).
To update a dependency by hand:
`uv lock --upgrade-package <name>`.

Runtime dependencies also carry an **upper bound** at the next major version
after the one currently pinned in `uv.lock` (for example `starlette>=0.37,<2`
while lock resolves starlette 1.x). That keeps `pip install keystone-mcp-gateway`
from pulling an untested major. Raising an upper bound — allowing the next
major — is a separate PR after the daily canary job has gone green on that
major.

### Private fastmcp/mcp APIs

Keystone calls several undocumented fastmcp and MCP SDK surfaces. Every such
symbol is listed in `tests/test_private_api_sentinels.py` (`PRIVATE_APIS`);
add a row there whenever you introduce a new private import or attribute
access. The daily `canary.yml` workflow runs the full suite against the newest
resolved versions and against the lowest allowed direct versions (`lowest-direct`
job); a green canary does not replace updating the sentinel table when you add
a dependency on a new private API.

## Running the tests

```bash
pytest -q
# or, with uv:
uv run pytest -q
```

The suite reads only `KEYSTONE_MCP_REDIS_URL` from your shell; other
`KEYSTONE_MCP_*` exports are cleared so local config cannot skew results.
Redis keys are written under `km:test:<run>:` and deleted at the end of the
run. PostgreSQL tests require `KEYSTONE_TEST_POSTGRES_URL` pointing at a
database whose name contains `test`; each pytest process uses its own schema.
In CI, any skip not listed in `tests/data/ci-allowed-skips.txt` fails the
build.

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

The suite must pass without reruns or forced ordering; a flaky test is a bug
to fix, not to retry (`tests/test_ci_hygiene.py`).

CI runs the pytest tree in two steps per Python version (core then tail, split
at ``tests/test_stdio_upstream_e2e.py`` via ``scripts/ci_pytest_shard.py``) so
each job stays under typical organization job-duration caps. Hypothesis ``fuzz`` tests run in the Security workflow, not
in the main test jobs. If a job ends with exit code **143** and no ``FAILED``
summary, check the log for ``--tb=short`` tracebacks first; an organization
may also cap job duration under **Settings → Actions** (repository or
``keystone-codes`` organization), which overrides ``timeout-minutes`` in
workflow YAML when the cap is lower.

Test-only key material lives in `tests/data/test-keys/` (secret scanners skip
it); a private key block anywhere else fails `tests/test_no_private_keys_in_repo.py`.

Changes to sign-in, OAuth, or RBAC that affect an attack from the release
checklist should add or update a test in `tests/security/` and an entry in
`tests/security/checklist.yaml` (see [security-model.md](security-model.md#how-this-is-tested)).

CI runs the suite on Python 3.11 through 3.14. Coverage (line and branch,
combined) is measured in the Python 3.12 job and must stay at or above the
``fail_under`` threshold in ``pyproject.toml`` (currently 86 %). Register new
pytest markers in ``pyproject.toml``; the suite runs with ``--strict-markers``.
Use a concrete exception type in ``pytest.raises(...)``, not bare
``Exception``.

Changing a protocol in `keystone_mcp.login` or `keystone_mcp.user_directory`
means changing the contract tests in the same pull request; the contract is
frozen from 0.5.0.

## Feature requests and the compatibility promise

Feature requests ask whether the idea would alter something listed in
[compatibility.md](compatibility.md). Maintainers label requests that would
change or remove a frozen contract as `contract-change`. Those changes belong
in a future 2.0 release, not in a 0.x minor, because the contract may only
grow until 2.0. If your request falls in that category, expect a reply pointing
to the compatibility page rather than a near-term implementation.

## Changing a public contract

Public contracts are listed in [compatibility.md](compatibility.md). The
baseline under `tests/data/frozen-baseline-0.5.0/` is generated from the
`v0.5.0` tag and must only change when the snapshot generator changes — never
edit it by hand. A new environment variable needs a `config.py` read,
`.env.example`, [environment.md](environment.md), a row in `compatibility.md`,
and an append to `tests/data/frozen-env-vars.txt` (policy keys and CLI commands
have their own append-only lists). New metrics, built-in tool arguments, and
plugin protocol members belong in `compatibility.md`; snapshots are regenerated
automatically. Frozen names cannot be removed or renamed before 2.0; changing a
default is allowed only as a documented security fix (`### Security` and
`### Migration` in the current changelog). Run
`uv run pytest tests/test_contract_freeze.py` locally before opening a pull
request.

## Security checks

CI runs a dependency audit (`uv audit`, OSV database) on every pull request
and weekly, and a container image scan (Trivy) on every pull request and
before every release. Both are blocking: a fixable CRITICAL or HIGH
vulnerability fails the build. See [`SECURITY.md`](../SECURITY.md).

Image scan blocks the pull request. To accept a finding temporarily, add it
to `.trivyignore` with a reason and a review date.

To run the same checks locally:

```bash
uv audit --frozen
```

```bash
docker build -t keystone-mcp:scan .
trivy image --severity CRITICAL,HIGH --ignore-unfixed --ignorefile .trivyignore keystone-mcp:scan
```

## Before opening a pull request

- `tests/test_no_legacy_terms.py` rejects internal labels of the original platform; use the neutral terms it suggests.
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

Once the tag is pushed, the `release.yml` workflow (`version-gate` → `test` →
`build-dist` → `wheel-smoke` → `image-build` → `image-scan` → `image-smoke`
→ `publish` → `pypi` → `github-release`) builds a multi-arch image once,
pushes it to GHCR by digest (no version tag yet), runs the same blocking
Trivy scan as the pull-request gate on that digest for both `linux/amd64`
and `linux/arm64`, pulls the amd64 digest and checks it over HTTP
(`scripts/smoke_image.sh`: `/healthz`, `/readyz`, the container
`HEALTHCHECK` status, and the non-root uid), then tags the digest with
`docker buildx imagetools create` and verifies the tagged manifest still
points at the scanned digest. A failed scan leaves an untagged digest in
GHCR (safe to delete manually; users never pull it). The workflow builds
the wheel and sdist with `uv build`, checks them against the same version
with `scripts/check_version.py --dist-dir`, installs the wheel into a clean
virtualenv for a second `/healthz`/`/readyz` smoke test
(`scripts/smoke_wheel.sh`), publishes the package to PyPI as
`keystone-mcp-gateway` via trusted publishing once the image is tagged,
and creates a GitHub Release whose notes are the matching `CHANGELOG.md`
section (`scripts/extract_changelog.py`). The `latest` tag is applied only
when the released version is the highest semver tag in the repository.
Base image digests in the `Dockerfile` are updated by Dependabot (`docker`
ecosystem); refresh them from the multi-arch manifest digest, not a
single-platform layer digest.

The first release ever needs a one-time, outside-this-repo setup: on
pypi.org, under the organization account, "Your projects → Publishing → Add
a new pending publisher" for PyPI project name `keystone-mcp-gateway`,
owner `keystone-codes`, repository `keystone-mcp`, workflow `release.yml`,
environment `pypi`; and in GitHub, Settings → Environments → create the
`pypi` environment (optionally with required reviewers). A fork without
that publisher configured sets the repository variable
`SKIP_PYPI_PUBLISH=true` to skip the `pypi` job without failing the release
(the same pattern as `SKIP_GHCR_PUSH` for the image).

A manual `workflow_dispatch` run always exercises the pipeline without
publishing to GHCR or PyPI: the `image-dry-run` job builds both platforms,
runs blocking Trivy scans, and smoke-tests amd64 locally. Tag pushes still
require `github.event_name == 'push'` for `image-build`, `publish`, `pypi`,
and `github-release`.
