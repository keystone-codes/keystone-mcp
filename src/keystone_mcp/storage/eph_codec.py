"""The ``eph:`` file_id codec.

An ephemeral upload is addressed by its object key wrapped in an ``eph:``
prefix, so a file_id can be handed through tool arguments without exposing a
bare storage key. Consumers of these ids outside this server must use the same
prefix and wrapping.
"""

from __future__ import annotations

EPH_PREFIX = "eph:"


def wrap_file_id(object_key: str) -> str:
    return f"{EPH_PREFIX}{object_key}"


def unwrap_file_id(file_id: str) -> str:
    if not file_id.startswith(EPH_PREFIX):
        raise ValueError("file_id_format_invalid")
    return file_id[len(EPH_PREFIX) :]
