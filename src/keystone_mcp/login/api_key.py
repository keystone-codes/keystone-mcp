"""``ApiKeyLoginProvider`` — the email + api_token form as a ``LoginProvider``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from keystone_mcp.login.base import FormLoginProviderBase
from keystone_mcp.login.protocol import FormField, LoginIdentity, LoginKind, LoginRejected
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.protocol import UserDirectoryResolver
from keystone_mcp.user_directory.util import email_folds_to_ascii, normalize_email
from keystone_mcp.users.models import utcnow


class ApiKeyLoginProvider(FormLoginProviderBase):
    """The api_token + email form as a ``form``-kind ``LoginProvider``."""

    def __init__(
        self,
        *,
        resolver: UserDirectoryResolver | None = None,
        dev_tokens: frozenset[str] = frozenset(),
        resolve_directory_keys: bool = False,
        enforce_directory_for_dev_tokens: bool = False,
    ) -> None:
        self._resolver = resolver
        self._dev_tokens = dev_tokens
        self._resolve_directory_keys = resolve_directory_keys
        self._enforce_directory_for_dev_tokens = enforce_directory_for_dev_tokens

    @property
    def wants_directory_resolver(self) -> bool:
        return self._resolve_directory_keys or self._enforce_directory_for_dev_tokens

    @property
    def name(self) -> str:
        return "api_key"

    @property
    def kind(self) -> LoginKind:
        return "form"

    @property
    def title(self) -> str:
        return "API key"

    @property
    def interactive(self) -> bool:
        return False

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def form_fields(self) -> Sequence[FormField]:
        return (
            FormField("email", "email", "email_label"),
            FormField("api_token", "password", "token_label"),
        )

    async def verify(self, form: Mapping[str, str]) -> LoginIdentity:
        raw_email = str(form.get("email", ""))
        if email_folds_to_ascii(raw_email):
            raise LoginRejected("invalid_credentials")
        email = normalize_email(raw_email)
        api_token = str(form.get("api_token", ""))
        if api_token in self._dev_tokens:
            return LoginIdentity(email=email, provider="api_key", interactive=False)
        if not self._resolve_directory_keys or self._resolver is None:
            raise LoginRejected("invalid_credentials")
        try:
            verification = await self._resolver.verify_api_key(api_token)
        except UserDirectoryUnavailableError:
            raise LoginRejected("provider_unavailable") from None
        if (
            verification is None
            or verification.subject_type != "human"
            or verification.subject != email
        ):
            raise LoginRejected("invalid_credentials")
        if verification.expires_at is not None and verification.expires_at <= utcnow():
            raise LoginRejected("invalid_credentials")
        return LoginIdentity(
            email=email,
            provider="api_key",
            interactive=False,
            key_id=verification.key_id,
            key_expires_at=verification.expires_at,
        )


def create_api_key_provider(config, context) -> ApiKeyLoginProvider:
    from keystone_mcp.config import Settings
    from keystone_mcp.plugins import LoginProviderConfig, PluginContext

    if not isinstance(config, LoginProviderConfig) or not isinstance(context, PluginContext):
        raise TypeError("invalid factory arguments")
    settings = context.settings
    if not isinstance(settings, Settings):
        raise TypeError("context.settings must be Settings")
    dev_set = frozenset(t for t in settings.dev_tokens.split(",") if t.strip())
    return ApiKeyLoginProvider(
        resolver=context.user_resolver,
        dev_tokens=dev_set,
        resolve_directory_keys=True,
        enforce_directory_for_dev_tokens=bool(dev_set),
    )
