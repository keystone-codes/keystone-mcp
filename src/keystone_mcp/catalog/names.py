"""Built-in administration tool names without adapter imports."""

from __future__ import annotations

BUILTIN_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "users_list",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
        "users_logout",
        "users_export",
        "users_delete",
        "service_accounts_list",
        "service_accounts_add",
        "service_accounts_update",
        "api_keys_issue",
        "api_keys_list",
        "api_keys_revoke",
        "policy_read",
        "policy_catalog",
        "policy_validate",
        "policy_role_set",
        "policy_role_delete",
        "policy_allow_add",
        "policy_allow_remove",
        "policy_list_set",
        "policy_rollback",
    }
)

READ_ONLY_ADMIN_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "users_list",
        "service_accounts_list",
        "api_keys_list",
        "policy_read",
        "policy_catalog",
        "policy_validate",
    }
)

MUTATING_ADMIN_TOOL_NAMES: frozenset[str] = BUILTIN_TOOL_NAMES - READ_ONLY_ADMIN_TOOL_NAMES
