"""Upstream egress security policy (env-driven)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UpstreamSecurityPolicy:
    allow_insecure_http: bool = False
    egress_allow_private: bool = False
