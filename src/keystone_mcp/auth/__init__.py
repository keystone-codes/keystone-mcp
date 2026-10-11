"""OAuth 2.1 authorization- and resource-server layer for keystone-mcp."""

from keystone_mcp.auth.identity_provider import (
    AuthServiceIdentityProvider,
    IdentityProvider,
    StaticIdentityProvider,
)
from keystone_mcp.auth.keystone_oauth_provider import KeystoneOAuthProvider
from keystone_mcp.auth.login_pending_store import (
    InMemoryLoginPendingStore,
    LoginPendingStore,
    RedisLoginPendingStore,
    build_login_pending_store,
)
from keystone_mcp.auth.oauth_store import (
    InMemoryOAuthStore,
    OAuthStore,
    RedisOAuthStore,
    build_oauth_store,
    build_shared_auth_stores,
)
from keystone_mcp.auth.throttle import LoginAttemptThrottle, PerIdentityThrottle

__all__ = [
    "AuthServiceIdentityProvider",
    "IdentityProvider",
    "StaticIdentityProvider",
    "KeystoneOAuthProvider",
    "InMemoryLoginPendingStore",
    "LoginPendingStore",
    "RedisLoginPendingStore",
    "InMemoryOAuthStore",
    "OAuthStore",
    "RedisOAuthStore",
    "build_login_pending_store",
    "build_oauth_store",
    "build_shared_auth_stores",
    "LoginAttemptThrottle",
    "PerIdentityThrottle",
]
