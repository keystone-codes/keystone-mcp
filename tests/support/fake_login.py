"""Fake ``LoginProvider`` implementations for exercising the generic login flow.

These exist so ``tests/test_login_flow_generic.py`` can prove that
``KeystoneOAuthProvider``'s login machinery (consent screen, CSRF/browser
binding, ``state``-keyed pending attempts, error-page mapping) works for
*any* conforming provider, not only the two built-in ones (Google, API key).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from keystone_mcp.login.protocol import (
    FormField,
    LoginIdentity,
    LoginKind,
    LoginRedirect,
    LoginRejected,
    LoginRejectReason,
)


class FakeRedirectProvider:
    """A minimal ``RedirectLoginProvider`` standing in for a real OIDC provider.

    ``begin`` returns a URL at a fictitious external host carrying ``state``,
    exactly as a real redirect provider would; ``complete`` reads the
    identity straight out of the callback's query params (``email=...``)
    instead of doing a real token exchange, or raises as directed by
    ``rejects``/``raises`` so a test can drive every branch of the generic
    callback handler without a real external service.
    """

    def __init__(
        self,
        name: str,
        *,
        title: str | None = None,
        interactive: bool = True,
        rejects: LoginRejectReason | None = None,
        raises: BaseException | None = None,
    ) -> None:
        self._name = name
        self._title = title if title is not None else name
        self._interactive = interactive
        self._rejects = rejects
        self._raises = raises
        self.begin_calls: list[dict[str, str]] = []
        self.complete_calls: list[dict[str, str]] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def kind(self) -> LoginKind:
        return "redirect"

    @property
    def title(self) -> str:
        return self._title

    @property
    def interactive(self) -> bool:
        return self._interactive

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def begin(self, *, state: str, callback_url: str) -> LoginRedirect:
        self.begin_calls.append({"state": state, "callback_url": callback_url})
        url = f"https://fake-provider.example/authorize?state={state}&provider={self._name}"
        return LoginRedirect(url=url, attempt={"marker": f"attempt-for-{state}"})

    async def complete(
        self, *, params: Mapping[str, str], callback_url: str, attempt: Mapping[str, str]
    ) -> LoginIdentity:
        self.complete_calls.append(dict(params))
        if self._raises is not None:
            raise self._raises
        if self._rejects is not None:
            raise LoginRejected(self._rejects, "fake provider rejected the attempt")
        return LoginIdentity(
            email=params.get("email", ""), provider=self._name, interactive=self._interactive
        )


class FakeFormProvider:
    """A minimal second ``FormLoginProvider``, used only to test that at most one is allowed."""

    def __init__(self, name: str) -> None:
        self._name = name

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
        return False

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def form_fields(self) -> Sequence[FormField]:
        return (FormField("email", "email", "email_label"),)

    async def verify(self, form: Mapping[str, str]) -> LoginIdentity:
        return LoginIdentity(email=form.get("email", ""), provider=self._name, interactive=False)
