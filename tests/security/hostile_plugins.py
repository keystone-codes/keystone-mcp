"""Hostile users-directory and login-provider stand-ins for SEC-20…SEC-25."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Any

from keystone_mcp.login.protocol import (
    FormField,
    LoginIdentity,
    LoginKind,
    LoginRedirect,
    LoginRejected,
)
from keystone_mcp.user_directory.types import UserResolveResult

# Re-export fake login helpers used by hostile login tests.
from support.fake_login import FakeFormProvider, FakeRedirectProvider  # noqa: F401


class HostileDirectoryBase:
    name = "hostile"
    capabilities = frozenset()

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


class HostileResolveDirectory(HostileDirectoryBase):
    """Directory whose ``resolve_user`` behaviour is configured per instance."""

    def __init__(self, *, result: UserResolveResult | None = None, behavior: str | None = None):
        self._result = result
        self._behavior = behavior

    async def resolve_user(self, subject: str) -> UserResolveResult:
        if self._behavior == "key_error":
            raise KeyError("hostile")
        if self._behavior == "connection_error":
            raise ConnectionError("hostile")
        if self._behavior == "runtime_error":
            raise RuntimeError("hostile")
        if self._behavior == "hang":
            await asyncio.sleep(3600)
        if self._behavior == "wrong_email":
            return UserResolveResult(
                exists=True,
                roles=("member",),
                is_blocked=False,
            )
        if self._behavior == "upper_email":
            return UserResolveResult(
                exists=True,
                roles=("member",),
                is_blocked=False,
            )
        if self._result is not None:
            return self._result
        return UserResolveResult(exists=False, roles=(), is_blocked=False)

    async def list_users(self, *, is_blocked=False, role=None, email_contains=None):
        return []


class HostileCapabilityDirectory(HostileDirectoryBase):
    """Declares a capability without implementing the matching protocol."""

    def __init__(self, capability: str) -> None:
        self.capabilities = frozenset({capability})

    async def resolve_user(self, subject: str) -> UserResolveResult:
        return UserResolveResult(exists=False, roles=(), is_blocked=False)

    async def list_users(self, *, is_blocked=False, role=None, email_contains=None):
        return []


class HostileFormLoginProvider:
    """Form login provider with configurable malicious behaviour."""

    def __init__(
        self,
        name: str = "hostile_form",
        *,
        email: str = "user@example.com",
        provider_name: str | None = None,
        full_name: str | None = None,
        behavior: str | None = None,
        allowed_domain: str | None = None,
    ) -> None:
        self._name = name
        self._email = email
        self._provider_name = provider_name if provider_name is not None else name
        self._full_name = full_name
        self._behavior = behavior
        self._allowed_domain = allowed_domain

    @property
    def name(self) -> str:
        return self._name

    @property
    def kind(self) -> LoginKind:
        return "form"

    @property
    def title(self) -> str:
        return self._name

    @property
    def interactive(self) -> bool:
        return True

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def form_fields(self) -> Sequence[FormField]:
        return (
            FormField("email", "email", "Email"),
            FormField("token", "password", "Token"),
        )

    async def verify(self, form: Mapping[str, str]) -> LoginIdentity:
        if self._behavior == "raise_runtime":
            raise RuntimeError("hostile verify")
        if self._behavior == "hang":
            await asyncio.sleep(3600)
        email = self._email if self._email else str(form.get("email", ""))
        if self._allowed_domain and not email.endswith("@" + self._allowed_domain):
            raise LoginRejected("domain_not_allowed", "domain not allowed")
        identity = LoginIdentity(
            email=email,
            provider=self._provider_name,
            interactive=True,
            full_name=self._full_name,
        )
        return identity


class HostileRedirectLoginProvider:
    """Redirect provider that returns dangerous or oversized redirect URLs."""

    def __init__(self, *, redirect_url: str, name: str = "hostile_redirect") -> None:
        self._name = name
        self._redirect_url = redirect_url

    @property
    def name(self) -> str:
        return self._name

    @property
    def kind(self) -> LoginKind:
        return "redirect"

    @property
    def title(self) -> str:
        return self._name

    @property
    def interactive(self) -> bool:
        return True

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def begin(self, *, state: str, callback_url: str) -> LoginRedirect:
        return LoginRedirect(url=self._redirect_url, attempt={"state": state})

    async def complete(
        self, *, params: Mapping[str, str], callback_url: str, attempt: Mapping[str, str]
    ) -> LoginIdentity:
        raise LoginRejected("invalid_request", "not used in hostile redirect tests")


def make_resolve_result(
    *,
    exists: Any = True,
    roles: Sequence[str] = ("member",),
    is_blocked: Any = False,
) -> UserResolveResult:
    """Build a resolve result with deliberately loose typing (plugin misbehaviour)."""
    exists_bool = exists if isinstance(exists, bool) else bool(exists)
    blocked_bool = is_blocked if isinstance(is_blocked, bool) else bool(is_blocked)
    if is_blocked is None:
        blocked_bool = False
    return UserResolveResult(
        exists=exists_bool,
        roles=tuple(str(r) for r in roles),
        is_blocked=blocked_bool,
    )
