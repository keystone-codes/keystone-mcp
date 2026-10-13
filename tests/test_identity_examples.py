"""Reference X-Keystone-Identity verifiers in examples/keystone-identity/.

These are standalone files (no dependency on keystone_mcp), loaded by path so
the tests exercise exactly what a service author would copy -- not an
importable package. See docs/connecting-services.md, section "Verifying the
identity assertion".
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import jwt
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATH = REPO_ROOT / "examples" / "keystone-identity" / "python" / "keystone_identity.py"
HELLO_COPY_PATH = REPO_ROOT / "examples" / "hello-upstream" / "keystone_identity.py"
TEST_VECTOR_PATH = REPO_ROOT / "examples" / "keystone-identity" / "test-vector.json"


def _load_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"_identity_ref_{path.stem}_{id(path)}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered under its own name before exec: the module's frozen
    # dataclass (KeystoneIdentity) has `from __future__ import annotations`
    # and needs to resolve its field types via sys.modules[__module__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def reference() -> ModuleType:
    return _load_module(REFERENCE_PATH)


@pytest.fixture(scope="module")
def vector() -> dict:
    return json.loads(TEST_VECTOR_PATH.read_text(encoding="utf-8"))


def test_python_reference_accepts_test_vector(reference, vector):
    """The vector is a fixed, already-expired token by design (see its own
    _comment) -- check signature, audience, issuer, typ and claim shape with
    exp verification turned off, the one carve-out that is test-only; the
    production verify_keystone_identity() never takes that option."""
    header = jwt.get_unverified_header(vector["token"])
    assert header["typ"] == reference.IDENTITY_TYP
    assert header["alg"] == "HS256"

    claims = jwt.decode(
        vector["token"],
        vector["secret"],
        algorithms=["HS256"],
        audience=vector["audience"],
        issuer=vector["issuer"],
        options={"verify_exp": False},
    )
    assert claims == vector["claims"]


def test_python_reference_rejects_tampered_token(reference, vector):
    head, payload, signature = vector["token"].split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{head}.{payload}.{tampered_signature}"

    with pytest.raises(reference.IdentityError):
        reference.verify_keystone_identity(
            tampered,
            secrets=[vector["secret"]],
            audience=vector["audience"],
            issuer=vector["issuer"],
        )


def test_python_reference_rejects_wrong_audience(reference, vector):
    with pytest.raises(reference.IdentityError):
        reference.verify_keystone_identity(
            vector["token"],
            secrets=[vector["secret"]],
            audience="some-other-upstream",
            issuer=vector["issuer"],
        )


def test_python_reference_rejects_alg_none(reference):
    header_b64 = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": reference.IDENTITY_TYP}).encode()
    ).rstrip(b"=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(
            {
                "iss": "https://keystone.example",
                "aud": "hello",
                "sub": "ann@example.com",
                "iat": 1700000000,
                "exp": 2000000000,
            }
        ).encode()
    ).rstrip(b"=")
    token = f"{header_b64.decode()}.{payload_b64.decode()}."

    with pytest.raises(reference.IdentityError):
        reference.verify_keystone_identity(
            token, secrets=["irrelevant-secret-but-at-least-32-bytes"], audience="hello"
        )


def test_python_reference_supports_two_secrets(reference, vector):
    """Secret rotation: the current (wrong-for-this-token) secret first,
    then the one the vector was actually signed with -- both reference
    verifiers try each in order, so a rotation never drops a live call."""
    identity = reference.verify_keystone_identity(
        vector["token"],
        secrets=["currently-configured-secret-unrelated-32b", vector["secret"]],
        audience=vector["audience"],
        issuer=vector["issuer"],
        leeway=10**12,  # the vector is long expired by the time this runs
    )
    assert identity.sub == vector["claims"]["sub"]
    assert identity.roles == tuple(vector["claims"]["roles"])


def test_hello_upstream_copy_matches_reference():
    """examples/hello-upstream/keystone_identity.py must be byte-identical to
    the reference it was copied from -- otherwise the two quietly drift
    apart and the demo stops proving what the docs claim it proves."""
    assert HELLO_COPY_PATH.read_bytes() == REFERENCE_PATH.read_bytes()
