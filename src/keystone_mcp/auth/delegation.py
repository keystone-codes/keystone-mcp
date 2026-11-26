"""``POST /auth/delegate``: a signed platform assertion plus a service API key.

Keystone (issuer ``keystone-platform``) sends a short ES256 assertion and the
project's ``ksk_`` service key. The gateway checks the signature against the
issuers file, the audience, the lifetime, and that ``jti`` has not been seen,
then writes a short access token with no refresh token.

The form field ``resource`` is the address Keystone will call. It is not
compared with this gateway and is not stored on the access token:
``verify_token`` rejects a token whose ``resource`` is not
``settings.resource_url``.
"""

from __future__ import annotations

import asyncio
import logging
import math
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import jwt
import yaml
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from mcp.server.auth.provider import AccessToken
from starlette.requests import Request
from starlette.responses import JSONResponse

from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.types import parse_service_subject, service_subject
from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from keystone_mcp.config import Settings
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.user_directory.protocol import UserDirectoryResolver

logger = logging.getLogger(__name__)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
ACTOR_TOKEN_TYPE = "urn:keystone:params:oauth:token-type:api-key"
DELEGATION_TYP = "keystone-delegation+jwt"
DELEGATION_CLIENT_ID = "keystone-delegation"
ISSUED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

ASSERTION_MAX_SECONDS = 60
IAT_FUTURE_SKEW_SECONDS = 30
_MODES = frozenset({"person", "service"})
_ISSUER_KEYS = frozenset({"public_key_file", "actors", "modes"})
_TOP_KEYS = frozenset({"version", "issuers"})
_FORM_FIELDS = (
    "grant_type",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "resource",
)
_EXACT_FORM = {
    "grant_type": GRANT_TYPE,
    "subject_token_type": SUBJECT_TOKEN_TYPE,
    "actor_token_type": ACTOR_TOKEN_TYPE,
}


class JtiStoreUnavailable(Exception):
    """The configured replay store could not record this ``jti``."""


class JtiStore(Protocol):
    async def claim(self, jti: str, ttl_seconds: int) -> bool: ...

    async def release(self, jti: str) -> None: ...


class MemoryJtiStore:
    """Replay memory for a single process, used only when Redis is not configured."""

    def __init__(self) -> None:
        self._until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def claim(self, jti: str, ttl_seconds: int) -> bool:
        now = time.time()
        async with self._lock:
            expired = [key for key, until in self._until.items() if until <= now]
            for key in expired:
                del self._until[key]
            if jti in self._until:
                return False
            self._until[jti] = now + ttl_seconds
            return True

    async def release(self, jti: str) -> None:
        async with self._lock:
            self._until.pop(jti, None)


class RedisJtiStore:
    """Shared replay memory. A Redis error is not treated as a fresh ``jti``."""

    def __init__(self, redis: Redis, key_prefix: str) -> None:
        self._redis = redis
        self._key_prefix = key_prefix

    def _key(self, jti: str) -> str:
        return f"{self._key_prefix}deleg:jti:{jti}"

    async def claim(self, jti: str, ttl_seconds: int) -> bool:
        from redis.exceptions import RedisError

        try:
            stored = await self._redis.set(self._key(jti), "1", nx=True, ex=ttl_seconds)
        except (RedisError, OSError, TimeoutError) as exc:
            raise JtiStoreUnavailable from exc
        return bool(stored)

    async def release(self, jti: str) -> None:
        from redis.exceptions import RedisError

        try:
            await self._redis.delete(self._key(jti))
        except (RedisError, OSError, TimeoutError):
            logger.warning("delegation jti release failed")


@dataclass(frozen=True, slots=True)
class DelegationIssuer:
    iss: str
    actors: frozenset[str]
    modes: frozenset[str]
    public_key: EllipticCurvePublicKey = field(repr=False)


@dataclass(frozen=True, slots=True)
class DelegationIssuers:
    by_name: dict[str, DelegationIssuer]

    def get(self, iss: str) -> DelegationIssuer | None:
        return self.by_name.get(iss)


@dataclass(frozen=True, slots=True)
class ParsedAssertion:
    iss: str
    mode: str
    jti: str
    exp: float
    sub: str | None
    kst_client: str
    kst_project: str
    kst_session: str
    requested_by: str | None
    requested_by_verified: bool | None


@dataclass
class _Facts:
    mode: str | None = None
    jti: str | None = None
    resource: str | None = None
    requested_by_verified: bool | None = None
    subject: str | None = None
    actor: str | None = None
    requested_by: str | None = None
    issuer: str | None = None
    kst_client: str | None = None
    kst_project: str | None = None
    kst_session: str | None = None


def load_delegation_issuers(path: str) -> DelegationIssuers:
    """Read the issuers file. ``ValueError`` text never includes key material."""
    raw_path = path.strip()
    if not raw_path:
        raise ValueError(
            "KEYSTONE_MCP_DELEGATION_ISSUERS_FILE is empty while "
            "KEYSTONE_MCP_DELEGATION_ENABLED=true"
        )
    try:
        text = Path(raw_path).read_text(encoding="utf-8")
    except OSError:
        raise ValueError(
            "KEYSTONE_MCP_DELEGATION_ISSUERS_FILE cannot be read or is not a file"
        ) from None
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        raise ValueError("KEYSTONE_MCP_DELEGATION_ISSUERS_FILE is not valid YAML") from None
    if not isinstance(document, dict):
        raise ValueError("KEYSTONE_MCP_DELEGATION_ISSUERS_FILE must be a mapping")
    extra = set(document) - _TOP_KEYS
    if extra:
        names = ", ".join(sorted(str(item) for item in extra))
        raise ValueError(f"KEYSTONE_MCP_DELEGATION_ISSUERS_FILE has unknown keys: {names}")
    if type(document.get("version")) is not int or document.get("version") != 1:
        raise ValueError("KEYSTONE_MCP_DELEGATION_ISSUERS_FILE version must be 1")
    issuers = document.get("issuers")
    if not isinstance(issuers, dict):
        raise ValueError("KEYSTONE_MCP_DELEGATION_ISSUERS_FILE issuers must be a mapping")
    loaded: dict[str, DelegationIssuer] = {}
    for name, record in issuers.items():
        if not isinstance(name, str) or not name:
            raise ValueError("KEYSTONE_MCP_DELEGATION_ISSUERS_FILE has an empty issuer name")
        loaded[name] = _load_issuer(name, record)
    return DelegationIssuers(by_name=loaded)


def _load_issuer(name: str, record: object) -> DelegationIssuer:
    label = f"KEYSTONE_MCP_DELEGATION_ISSUERS_FILE issuer {name!r}"
    if not isinstance(record, dict):
        raise ValueError(f"{label} must be a mapping")
    extra = set(record) - _ISSUER_KEYS
    if extra:
        names = ", ".join(sorted(str(item) for item in extra))
        raise ValueError(f"{label} has unknown keys: {names}")
    if "public_key_file" not in record or "actors" not in record:
        raise ValueError(f"{label} requires public_key_file and actors")
    key_path = record.get("public_key_file")
    if not isinstance(key_path, str) or not key_path.strip():
        raise ValueError(f"{label} public_key_file must be a path")
    public_key = _load_public_key(label, key_path.strip())
    actors_raw = record.get("actors")
    if not isinstance(actors_raw, list):
        raise ValueError(f"{label} actors must be a list")
    actors: set[str] = set()
    for item in actors_raw:
        if not isinstance(item, str):
            raise ValueError(f"{label} actors must be service subjects (svc:<name>)")
        parsed = parse_service_subject(item.strip().lower())
        if parsed is None:
            raise ValueError(f"{label} actors must be service subjects (svc:<name>)")
        actors.add(service_subject(parsed))
    if "modes" not in record:
        modes = set(_MODES)
    else:
        modes_raw = record.get("modes")
        if not isinstance(modes_raw, list):
            raise ValueError(f"{label} modes must be a list")
        modes = set()
        for item in modes_raw:
            if not isinstance(item, str) or item not in _MODES:
                raise ValueError(f"{label} has an unknown mode")
            modes.add(item)
    return DelegationIssuer(
        iss=name,
        actors=frozenset(actors),
        modes=frozenset(modes),
        public_key=public_key,
    )


def _load_public_key(label: str, path: str) -> EllipticCurvePublicKey:
    try:
        pem = Path(path).read_text(encoding="utf-8")
    except OSError:
        raise ValueError(f"{label} public key file cannot be read") from None
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, TypeError):
        raise ValueError(f"{label} public key is not a PEM EC P-256 key") from None
    if not isinstance(key, EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError(f"{label} public key is not a PEM EC P-256 key")
    return key


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def _nonempty_str(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value


def _canonical_subject(value: str) -> str:
    parsed = parse_service_subject(value.strip().lower())
    if parsed is not None:
        return service_subject(parsed)
    return normalize_email(value)


def _log_token(value: str | None) -> str:
    if not value:
        return "-"
    cleaned = value.replace("\n", "").replace("\r", "")
    return cleaned[:128]


class DelegationExchange:
    """One mounted ``POST /auth/delegate`` handler."""

    def __init__(
        self,
        *,
        settings: Settings,
        issuers: DelegationIssuers,
        store: Any,
        resolver: UserDirectoryResolver | None,
        redis: Redis | None,
        observability: RbacObservability | None,
    ) -> None:
        self._settings = settings
        self._issuers = issuers
        self._store = store
        self._resolver = resolver
        self._observability = observability
        self._jti: JtiStore
        if redis is not None:
            self._jti = RedisJtiStore(redis, settings.redis_key_prefix)
        else:
            self._jti = MemoryJtiStore()

    async def handle(self, request: Request) -> JSONResponse:
        facts = _Facts()
        form = await _read_form(request)
        if form is None:
            return self._finish(facts, outcome="denied", reason="invalid_request")
        facts.resource = form["resource"]

        parsed, code = _parse_assertion(
            form["subject_token"],
            issuers=self._issuers,
            base_url=self._settings.base_url,
        )
        if code is not None or parsed is None:
            issuer_name = _unverified_issuer(form["subject_token"])
            facts.issuer = issuer_name
            return self._finish(facts, outcome="denied", reason=code or "bad_signature")

        facts.issuer = parsed.iss
        facts.mode = parsed.mode
        facts.jti = parsed.jti
        facts.kst_client = parsed.kst_client
        facts.kst_project = parsed.kst_project
        facts.kst_session = parsed.kst_session
        facts.requested_by = parsed.requested_by
        facts.requested_by_verified = parsed.requested_by_verified
        if parsed.mode == "person" and parsed.sub is not None:
            facts.subject = normalize_email(parsed.sub)

        ttl = max(1, math.ceil(parsed.exp - time.time()))
        try:
            fresh = await self._jti.claim(parsed.jti, ttl)
        except JtiStoreUnavailable:
            return self._finish(facts, outcome="unavailable", reason="temporarily_unavailable")
        if not fresh:
            return self._finish(facts, outcome="denied", reason="replay")

        if self._resolver is None:
            await self._jti.release(parsed.jti)
            return self._finish(facts, outcome="unavailable", reason="temporarily_unavailable")

        try:
            actor, actor_code = await self._verify_actor(form["actor_token"], parsed.iss)
        except UserDirectoryUnavailableError:
            await self._jti.release(parsed.jti)
            return self._finish(facts, outcome="unavailable", reason="temporarily_unavailable")
        if actor_code is not None or actor is None:
            return self._finish(facts, outcome="denied", reason=actor_code or "unknown_actor")
        facts.actor = actor

        try:
            subject, subject_type, subject_code = await self._verify_subject(parsed, actor)
        except UserDirectoryUnavailableError:
            await self._jti.release(parsed.jti)
            return self._finish(facts, outcome="unavailable", reason="temporarily_unavailable")
        if subject_code is not None or subject is None or subject_type is None:
            if subject_code == "actor_mismatch" and parsed.sub is not None:
                facts.subject = parsed.sub
            return self._finish(facts, outcome="denied", reason=subject_code or "subject_unknown")
        facts.subject = subject

        try:
            token, expires_in = await self._issue(
                parsed, subject=subject, subject_type=subject_type, actor=actor
            )
        except Exception:
            await self._jti.release(parsed.jti)
            logger.warning("delegation token store failed")
            return self._finish(facts, outcome="unavailable", reason="temporarily_unavailable")

        self._finish(facts, outcome="issued", reason=None)
        return JSONResponse(
            {
                "access_token": token,
                "token_type": "Bearer",
                "issued_token_type": ISSUED_TOKEN_TYPE,
                "expires_in": expires_in,
            }
        )

    async def _verify_actor(self, key: str, issuer_name: str) -> tuple[str | None, str | None]:
        issuer = self._issuers.get(issuer_name)
        if issuer is None or self._resolver is None:
            return None, "unknown_actor"
        verification = await self._resolver.verify_api_key(key)
        if verification is None:
            return None, "unknown_actor"
        if verification.subject_type != "service":
            return None, "actor_not_service"
        actor = _canonical_subject(verification.subject)
        if actor not in issuer.actors:
            return None, "unknown_actor"
        resolved = await self._resolver.resolve(actor, critical=True)
        if not resolved.exists:
            return None, "unknown_actor"
        if resolved.is_blocked:
            return None, "actor_blocked"
        return actor, None

    async def _verify_subject(
        self, parsed: ParsedAssertion, actor: str
    ) -> tuple[str | None, str | None, str | None]:
        if parsed.mode == "service":
            if parsed.sub is not None and _canonical_subject(parsed.sub) != actor:
                return None, None, "actor_mismatch"
            return actor, "service", None
        if self._resolver is None or parsed.sub is None:
            return None, None, "subject_unknown"
        subject = normalize_email(parsed.sub)
        resolved = await self._resolver.resolve(subject, critical=True)
        if not resolved.exists:
            return None, None, "subject_unknown"
        if resolved.is_blocked:
            return None, None, "subject_blocked"
        if resolved.subject_type != "human":
            return None, None, "subject_not_human"
        return subject, "human", None

    async def _issue(
        self,
        parsed: ParsedAssertion,
        *,
        subject: str,
        subject_type: str,
        actor: str,
    ) -> tuple[str, int]:
        expires_in = self._settings.delegation_token_ttl_seconds
        now = int(time.time())
        token = f"km_at_{secrets.token_urlsafe(32)}"
        claims: dict[str, Any] = {
            "auth_method": "delegation",
            "subject_type": subject_type,
            "interactive": False,
            "iat": now,
            "act": {"sub": actor},
            "delegation_jti": parsed.jti,
        }
        if subject_type == "human":
            claims["email"] = subject
        if parsed.requested_by is not None:
            claims["requested_by"] = parsed.requested_by
            claims["requested_by_verified"] = bool(parsed.requested_by_verified)
        access = AccessToken(
            token=token,
            client_id=DELEGATION_CLIENT_ID,
            scopes=[],
            expires_at=now + expires_in,
            resource=self._settings.resource_url,
            subject=subject,
            claims=claims,
        )
        await self._store.put_access_token(access)
        return token, expires_in

    def _finish(self, facts: _Facts, *, outcome: str, reason: str | None) -> JSONResponse:
        try:
            if self._observability is not None:
                self._observability.authz_audit.record_delegation_exchange(
                    outcome=outcome,
                    reason=reason,
                    mode=facts.mode,
                    delegation_jti=facts.jti,
                    resource=facts.resource,
                    requested_by_verified=facts.requested_by_verified,
                    subject=facts.subject,
                    actor=facts.actor,
                    requested_by=facts.requested_by,
                    kst_client=facts.kst_client,
                    kst_project=facts.kst_project,
                    kst_session=facts.kst_session,
                )
                self._observability.metrics.record_delegation_exchange(
                    result=outcome,
                    reason=reason or "none",
                )
        except Exception:
            logger.warning("delegation exchange audit failed")
        logger.info(
            "delegation exchange issuer=%s mode=%s outcome=%s reason=%s",
            _log_token(facts.issuer),
            facts.mode or "-",
            outcome,
            reason or "-",
        )
        if outcome == "unavailable":
            return JSONResponse(
                {
                    "error": "temporarily_unavailable",
                    "error_description": "temporarily_unavailable",
                },
                status_code=503,
            )
        return JSONResponse(
            {"error": "invalid_grant", "error_description": reason or "invalid_request"},
            status_code=400,
        )


async def _read_form(request: Request) -> dict[str, str] | None:
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media != "application/x-www-form-urlencoded":
        return None
    try:
        form = await request.form()
    except Exception:
        return None
    values: dict[str, str] = {}
    for name in _FORM_FIELDS:
        raw = form.get(name)
        if not isinstance(raw, str) or not raw:
            return None
        values[name] = raw
    for name, expected in _EXACT_FORM.items():
        if values[name] != expected:
            return None
    return values


def _unverified_issuer(token: str) -> str | None:
    try:
        claims = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["ES256"],
        )
    except jwt.InvalidTokenError:
        return None
    iss = claims.get("iss") if isinstance(claims, dict) else None
    if not isinstance(iss, str) or not iss:
        return None
    return iss


def _parse_assertion(
    token: str,
    *,
    issuers: DelegationIssuers,
    base_url: str,
) -> tuple[ParsedAssertion | None, str | None]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        return None, "bad_signature"
    if header.get("alg") != "ES256" or header.get("typ") != DELEGATION_TYP:
        return None, "bad_signature"
    issuer_name = _unverified_issuer(token)
    issuer = issuers.get(issuer_name) if issuer_name else None
    if issuer is None:
        return None, "bad_signature"
    try:
        claims = jwt.decode(
            token,
            issuer.public_key,
            algorithms=["ES256"],
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.InvalidTokenError:
        return None, "bad_signature"
    if not isinstance(claims, dict) or claims.get("iss") != issuer.iss:
        return None, "bad_signature"

    aud = claims.get("aud")
    if not isinstance(aud, str) or _strip_one_slash(aud) != _strip_one_slash(base_url):
        return None, "bad_audience"

    iat = _number(claims.get("iat"))
    exp = _number(claims.get("exp"))
    if iat is None or exp is None:
        return None, "invalid_request"
    now = time.time()
    if exp <= now:
        return None, "expired"
    if exp > iat + ASSERTION_MAX_SECONDS or iat > now + IAT_FUTURE_SKEW_SECONDS or exp < iat:
        return None, "assertion_ttl"

    mode = claims.get("kst_mode")
    if not isinstance(mode, str) or mode not in _MODES:
        return None, "invalid_request"
    if mode not in issuer.modes:
        return None, "mode_not_allowed"

    jti_raw = claims.get("jti")
    if not isinstance(jti_raw, str):
        return None, "invalid_request"
    try:
        jti = str(uuid.UUID(jti_raw))
    except ValueError:
        return None, "invalid_request"

    kst_client = _nonempty_str(claims.get("kst_client"))
    kst_project = _nonempty_str(claims.get("kst_project"))
    kst_session = _nonempty_str(claims.get("kst_session"))
    if kst_client is None or kst_project is None or kst_session is None:
        return None, "invalid_request"

    sub = claims.get("sub", None)
    if sub is not None and not isinstance(sub, str):
        return None, "invalid_request"
    if isinstance(sub, str) and not sub:
        sub = None
    if mode == "person" and sub is None:
        return None, "invalid_request"

    requested_by = claims.get("kst_requested_by", None)
    verified = claims.get("kst_requested_by_verified", None)
    if requested_by is not None and not isinstance(requested_by, str):
        return None, "invalid_request"
    if isinstance(requested_by, str) and not requested_by:
        requested_by = None
    if verified is not None and not isinstance(verified, bool):
        return None, "invalid_request"
    if verified is True and requested_by is None:
        return None, "invalid_request"
    if requested_by is not None and not isinstance(verified, bool):
        return None, "invalid_request"

    return (
        ParsedAssertion(
            iss=issuer.iss,
            mode=mode,
            jti=jti,
            exp=exp,
            sub=sub,
            kst_client=kst_client,
            kst_project=kst_project,
            kst_session=kst_session,
            requested_by=requested_by if isinstance(requested_by, str) else None,
            requested_by_verified=verified if isinstance(verified, bool) else None,
        ),
        None,
    )


def _strip_one_slash(value: str) -> str:
    if value.endswith("/"):
        return value[:-1]
    return value
