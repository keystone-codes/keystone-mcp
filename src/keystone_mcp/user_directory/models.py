"""Deprecated location of ``UserResolveResult`` -- re-exported from ``types``.

``UserResolveResult`` moved to :mod:`keystone_mcp.user_directory.types`
alongside ``UserRecord`` and ``MutationResult``. Import it from there;
this module is kept only so existing imports of
``keystone_mcp.user_directory.models.UserResolveResult`` keep working.
"""

from __future__ import annotations

from keystone_mcp.user_directory.types import UserResolveResult

__all__ = ["UserResolveResult"]
