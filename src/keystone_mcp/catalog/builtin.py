"""The routes every keystone-mcp deployment publishes.

These are the domain-neutral tools the server owns itself, as opposed to the
tools it proxies from configured upstreams (see
:mod:`keystone_mcp.router.upstream`). Two groups:

File transfer — keeps large binaries out of MCP tool-call JSON by handing the
caller a short-lived signed URL instead of bytes. Registered only when
``KEYSTONE_MCP_FILE_API_URL`` is set:
  - ``create_upload_url`` mints a signed PUT link plus the ``file_id`` to pass
    on to whichever import tool consumes the upload.
  - ``get_download_link`` mints a signed download link for a stored object.

User administration — administration of the users directory, used to manage
who may reach this server and with which roles: ``users_list``,
``users_add``, ``users_update``, ``users_block``, ``users_unblock``,
``users_set_roles``, ``users_grant_role``, ``users_revoke_role``. These routes
are registered only when ``KEYSTONE_MCP_RBAC_MODE=enforce``; authorization is
RBAC policy plus the RBAC middleware. The ``admin=True`` flag is catalog
metadata only and enforces nothing. ``users_list`` is published whenever a
directory is configured; the other seven (administration) are published only
when that directory declares the ``"admin"`` capability (X06) -- a read-only
directory publishes ``users_list`` alone.

Every route here is registered ``mode="live"`` — its adapter is wired and
serving. Add a route with ``registry.add_route`` when a new built-in target is
ready.
"""

from __future__ import annotations

import logging

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.file_ref import FileRefAdapter
from keystone_mcp.adapters.upload_url import UploadUrlAdapter
from keystone_mcp.adapters.users_admin import RoleSource, UsersAdminAdapter
from keystone_mcp.config import Settings
from keystone_mcp.router.registry import Param, RouterRegistry
from keystone_mcp.user_directory.protocol import UserDirectory

logger = logging.getLogger(__name__)

#: Every tool name the built-in catalog can register, whatever the settings.
#: Used by upstream namespace validation (P09) to reject namespaces that
#: would publish a colliding ``<namespace>_<tool>`` name.
BUILTIN_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "create_upload_url",
        "get_download_link",
        "users_list",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
    }
)


def register_catalog(
    registry: RouterRegistry,
    settings: Settings,
    *,
    observability: object | None = None,
    directory: UserDirectory | None = None,
    role_source: RoleSource | None = None,
) -> None:
    users_admin = UsersAdminAdapter(
        directory=directory, observability=observability, role_source=role_source
    )

    P = Param  # noqa: N806 — local alias for brevity

    # ── File transfer (optional): only when KEYSTONE_MCP_FILE_API_URL is set ──
    if settings.file_tools_enabled:
        upload_url = UploadUrlAdapter(settings.resolved_file_api_base_url)
        file_ref = FileRefAdapter(settings.resolved_file_api_base_url)

        registry.add_route(
            "create_upload_url",
            upload_url,
            pattern=Pattern.M_U,
            params=[
                P("filename", str, required=False, default=None),
                P("content_type", str, required=False, default=None),
            ],
            description=(
                "Create a short-lived signed URL for uploading one file. Returns "
                "upload_url, file_id, expires_at and max_bytes. PUT the file bytes "
                "to upload_url, then pass file_id to the tool that imports the "
                "file. Keeps large files out of tool arguments."
            ),
            mode="live",
        )
        registry.add_route(
            "get_download_link",
            file_ref,
            pattern=Pattern.M_D,
            params=[P("file_id", str)],
            description=(
                "Create a short-lived signed download link for a stored file. "
                "Returns file_url and expires_at."
            ),
            mode="live",
        )

    if not settings.rbac_enforcing:
        return
    if directory is None:
        return

    # ── ADMIN — user administration over whichever UserDirectory the server
    # was built with. Who may call these tools is decided by the policy file.
    # ``admin=True`` is catalog metadata only. ``users_list`` is published for
    # any directory; the other seven only when it declares "admin" (X06).
    _read_only_tools: list[tuple[str, str, list[Param]]] = [
        (
            "users_list",
            "List workspace users with optional filters (default: not blocked).",
            [
                P("is_blocked", bool, required=False, default=False),
                P("role", str, required=False, default=None),
                P("email_contains", str, required=False, default=None),
            ],
        ),
    ]
    _admin_tools: list[tuple[str, str, list[Param]]] = [
        (
            "users_add",
            "Create a workspace user with an initial role set.",
            [
                P("email", str),
                P("full_name", str),
                P("roles", list, required=False, default=None),
                P("note", str, required=False, default=None),
            ],
        ),
        (
            "users_update",
            "Update a user profile (full_name and/or note).",
            [
                P("email", str),
                P("full_name", str, required=False, default=None),
                P("note", str, required=False, default=None),
            ],
        ),
        (
            "users_block",
            "Block a user account (requires verified administrator actor).",
            [P("email", str)],
        ),
        (
            "users_unblock",
            "Unblock a previously blocked user account.",
            [P("email", str)],
        ),
        (
            "users_set_roles",
            "Replace the full role set for a user (multi-role model).",
            [
                P("email", str),
                P("roles", list),
            ],
        ),
        (
            "users_grant_role",
            "Grant a single role to a user.",
            [
                P("email", str),
                P("role", str),
            ],
        ),
        (
            "users_revoke_role",
            "Revoke a single role from a user.",
            [
                P("email", str),
                P("role", str),
            ],
        ),
    ]
    for tool_name, description, params in _read_only_tools:
        registry.add_route(
            tool_name,
            users_admin,
            pattern=Pattern.M_B,
            params=params,
            description=description,
            mode="live",
            admin=True,
        )
    if "admin" in directory.capabilities:
        for tool_name, description, params in _admin_tools:
            registry.add_route(
                tool_name,
                users_admin,
                pattern=Pattern.M_B,
                params=params,
                description=description,
                mode="live",
                admin=True,
            )
    else:
        logger.warning(
            "users directory %s is read-only: users_* administration tools are not published",
            directory.name,
        )
