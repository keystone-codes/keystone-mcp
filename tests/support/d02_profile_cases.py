"""Profile case table for config hardening acceptance tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ProfileName = Literal["local", "production"]
Expectation = Literal["ok", "config_error", "build_server_error"]


@dataclass(frozen=True)
class ProfileCase:
    id: str
    profile: ProfileName
    env: dict[str, str] = field(default_factory=dict)
    unset: tuple[str, ...] = ()
    expect: Expectation = "ok"
    warnings: frozenset[str] = frozenset()
    forbid_warnings: frozenset[str] = frozenset()
    check_audit_enabled: bool | None = None
    check_log_redact: bool | None = None
    check_oauth_dcr: bool | None = None
    use_build_server: bool = False


WARNING_MARKERS: dict[str, str] = {
    "W8": "path, query, or fragment",
    "W9": "TOKEN_TTL is longer than 86400",
    "W10": "AUTH_CODE_TTL is longer than 600",
    "W11_short": "shorter than 16 bytes",
    "W11_empty": "audit records are not pseudonymous",
    "W12": "/0 network",
    "W13": "RBAC_AUDIT_ENABLED=false in production",
    "W14": "LOG_REDACT=false in production",
    "W15": "LOG_LEVEL=DEBUG in production",
    "W16": "uses redis:// to a non-loopback",
    "W17": "REFRESH_INTERVAL_SECONDS is negative while RBAC is off",
    "W18": "FORWARDED_ALLOW_IPS is not set",
    "W19": "empty value and is read as false",
}


def _expand(case_id: str, env: dict[str, str], **kwargs) -> tuple[ProfileCase, ProfileCase]:
    return (
        ProfileCase(id=f"{case_id}_local", profile="local", env=env, **kwargs),
        ProfileCase(id=f"{case_id}_production", profile="production", env=env, **kwargs),
    )


def _local_only(case_id: str, env: dict[str, str], **kwargs) -> tuple[ProfileCase, ...]:
    return (ProfileCase(id=f"{case_id}_local", profile="local", env=env, **kwargs),)


def _production_only(case_id: str, env: dict[str, str], **kwargs) -> tuple[ProfileCase, ...]:
    return (ProfileCase(id=f"{case_id}_production", profile="production", env=env, **kwargs),)


PROFILE_CASES: tuple[ProfileCase, ...] = (
    *_expand(
        "rbac_audit_enabled_true_space",
        {"KEYSTONE_MCP_RBAC_AUDIT_ENABLED": "True "},
        check_audit_enabled=True,
    ),
    ProfileCase(
        id="log_redact_on_local",
        profile="local",
        env={"KEYSTONE_MCP_LOG_REDACT": "on"},
        check_log_redact=True,
    ),
    ProfileCase(
        id="log_redact_on_production",
        profile="production",
        env={"KEYSTONE_MCP_LOG_REDACT": "on"},
        check_log_redact=True,
    ),
    ProfileCase(
        id="log_redact_off_local",
        profile="local",
        env={"KEYSTONE_MCP_LOG_REDACT": "OFF"},
        check_log_redact=False,
    ),
    ProfileCase(
        id="log_redact_off_production",
        profile="production",
        env={"KEYSTONE_MCP_LOG_REDACT": "OFF"},
        check_log_redact=False,
        warnings=frozenset({"W14"}),
    ),
    *_expand(
        "oauth_dcr_enabled_typo",
        {"KEYSTONE_MCP_OAUTH_DCR_ENABLED": "enabled"},
        expect="config_error",
    ),
    *_expand(
        "oauth_dcr_empty",
        {"KEYSTONE_MCP_OAUTH_DCR_ENABLED": ""},
        check_oauth_dcr=False,
        warnings=frozenset({"W19"}),
    ),
    *_expand(
        "token_ttls_non_positive",
        {
            "KEYSTONE_MCP_TOKEN_TTL": "-5",
            "KEYSTONE_MCP_AUTH_CODE_TTL": "0",
            "KEYSTONE_MCP_REFRESH_TOKEN_TTL": "0",
        },
        expect="config_error",
    ),
    *_expand(
        "token_ttl_172800",
        {"KEYSTONE_MCP_TOKEN_TTL": "172800"},
        warnings=frozenset({"W9"}),
    ),
    *_expand(
        "auth_code_ttl_3600",
        {"KEYSTONE_MCP_AUTH_CODE_TTL": "3600"},
        warnings=frozenset({"W10"}),
    ),
    *_expand("port_zero", {"KEYSTONE_MCP_PORT": "0"}, expect="config_error"),
    *_expand("port_99999", {"KEYSTONE_MCP_PORT": "99999"}, expect="config_error"),
    *_expand(
        "base_url_no_scheme", {"KEYSTONE_MCP_BASE_URL": "mcp.example.com"}, expect="config_error"
    ),
    *_expand(
        "base_url_ftp", {"KEYSTONE_MCP_BASE_URL": "ftp://mcp.example.com"}, expect="config_error"
    ),
    *_expand(
        "base_url_https_no_host", {"KEYSTONE_MCP_BASE_URL": "https://"}, expect="config_error"
    ),
    *_production_only(
        "base_url_with_path",
        {"KEYSTONE_MCP_BASE_URL": "https://mcp.example.com/sub/"},
        warnings=frozenset({"W8"}),
    ),
    *_local_only(
        "base_url_local_path_query",
        {"KEYSTONE_MCP_BASE_URL": "http://localhost:8080/sub?x=1"},
        warnings=frozenset({"W8"}),
    ),
    *_expand(
        "log_request_id_header_empty",
        {"KEYSTONE_MCP_LOG_REQUEST_ID_HEADER": ""},
        expect="config_error",
    ),
    *_expand(
        "log_request_id_header_invalid",
        {"KEYSTONE_MCP_LOG_REQUEST_ID_HEADER": "X Request"},
        expect="config_error",
    ),
    *_expand(
        "metrics_path_no_slash",
        {"KEYSTONE_MCP_METRICS_ENABLED": "true", "KEYSTONE_MCP_METRICS_PATH": "metrics"},
        expect="config_error",
    ),
    *_expand(
        "metrics_path_same_as_http",
        {
            "KEYSTONE_MCP_METRICS_ENABLED": "true",
            "KEYSTONE_MCP_METRICS_PATH": "/mcp",
            "KEYSTONE_MCP_HTTP_PATH": "/mcp",
        },
        expect="config_error",
    ),
    *_expand(
        "metrics_disabled_bad_path",
        {"KEYSTONE_MCP_METRICS_ENABLED": "false", "KEYSTONE_MCP_METRICS_PATH": "metrics"},
    ),
    *_local_only(
        "redis_empty_rbac_off",
        {"KEYSTONE_MCP_REDIS_URL": "", "KEYSTONE_MCP_RBAC_MODE": "off"},
        expect="config_error",
    ),
    *_expand(
        "audit_salt_short",
        {"KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT": "x"},
        warnings=frozenset({"W11_short"}),
    ),
    *_local_only(
        "audit_on_empty_salt_rbac_off",
        {
            "KEYSTONE_MCP_RBAC_MODE": "off",
            "KEYSTONE_MCP_RBAC_AUDIT_ENABLED": "true",
            "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT": "",
        },
        warnings=frozenset({"W11_empty"}),
    ),
    *_expand(
        "internal_cidr_any",
        {"KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS": "0.0.0.0/0,::/0"},
        warnings=frozenset({"W12"}),
    ),
    ProfileCase(
        id="rbac_audit_disabled_local",
        profile="local",
        env={"KEYSTONE_MCP_RBAC_AUDIT_ENABLED": "false"},
    ),
    ProfileCase(
        id="rbac_audit_disabled_production",
        profile="production",
        env={"KEYSTONE_MCP_RBAC_AUDIT_ENABLED": "false"},
        warnings=frozenset({"W13"}),
    ),
    ProfileCase(
        id="log_level_debug_local",
        profile="local",
        env={"KEYSTONE_MCP_LOG_LEVEL": "DEBUG"},
    ),
    ProfileCase(
        id="log_level_debug_production",
        profile="production",
        env={"KEYSTONE_MCP_LOG_LEVEL": "DEBUG"},
        warnings=frozenset({"W15"}),
    ),
    ProfileCase(
        id="redis_remote_no_tls_local",
        profile="local",
        env={"KEYSTONE_MCP_REDIS_URL": "redis://:pw@redis.example.com:6379/0"},
    ),
    ProfileCase(
        id="redis_remote_no_tls_production",
        profile="production",
        env={"KEYSTONE_MCP_REDIS_URL": "redis://:pw@redis.example.com:6379/0"},
        warnings=frozenset({"W16"}),
    ),
    *_expand(
        "redis_rediss_remote",
        {"KEYSTONE_MCP_REDIS_URL": "rediss://:pw@redis.example.com:6380/0"},
        forbid_warnings=frozenset({"W16"}),
    ),
    *_expand(
        "redis_loopback",
        {"KEYSTONE_MCP_REDIS_URL": "redis://" + "localhost:6379/0"},
        forbid_warnings=frozenset({"W16"}),
    ),
    *_local_only(
        "refresh_interval_negative_rbac_off",
        {"KEYSTONE_MCP_RBAC_MODE": "off", "KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS": "-1"},
        warnings=frozenset({"W17"}),
    ),
    ProfileCase(
        id="host_all_interfaces_no_forwarded_local",
        profile="local",
        env={"KEYSTONE_MCP_HOST": "0.0.0.0"},
        unset=("FORWARDED_ALLOW_IPS",),
    ),
    ProfileCase(
        id="host_all_interfaces_no_forwarded_production",
        profile="production",
        env={"KEYSTONE_MCP_HOST": "0.0.0.0"},
        unset=("FORWARDED_ALLOW_IPS",),
        warnings=frozenset({"W18"}),
    ),
    ProfileCase(
        id="host_all_interfaces_with_forwarded_local",
        profile="local",
        env={"KEYSTONE_MCP_HOST": "0.0.0.0", "FORWARDED_ALLOW_IPS": "10.0.0.0/8"},
        forbid_warnings=frozenset({"W18"}),
    ),
    ProfileCase(
        id="host_all_interfaces_with_forwarded_production",
        profile="production",
        env={"KEYSTONE_MCP_HOST": "0.0.0.0", "FORWARDED_ALLOW_IPS": "10.0.0.0/8"},
        forbid_warnings=frozenset({"W18"}),
    ),
    ProfileCase(
        id="plugin_interactive_with_api_key_local",
        profile="local",
        use_build_server=True,
    ),
    ProfileCase(
        id="plugin_interactive_with_api_key_production",
        profile="production",
        use_build_server=True,
        expect="build_server_error",
    ),
)
