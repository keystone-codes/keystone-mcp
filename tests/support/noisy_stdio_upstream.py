"""A stdio MCP upstream that floods stderr before it starts serving MCP.

Used by ``test_start_reaches_running_despite_noisy_startup_stderr`` in
``tests/test_stdio_process.py`` to prove that
:class:`~keystone_mcp.router.stdio_process.StdioUpstreamProcess` drains
stderr from the moment the pipe exists, not only after ``initialize``
succeeds. A child that writes more than a pipe's kernel buffer (commonly
64 KiB) to stderr before anyone reads the other end would otherwise block on
``write()``, hanging startup forever.

Serves the same tools as ``stdio_upstream.py`` (imported, not duplicated)
once the flood is written.
"""

from __future__ import annotations

import sys

import anyio
from stdio_upstream import main

#: Comfortably larger than a typical 64 KiB pipe buffer.
_NOISY_BYTES = 256 * 1024


def _flood_stderr() -> None:
    sys.stderr.write("x" * _NOISY_BYTES + "\n")
    sys.stderr.flush()


if __name__ == "__main__":
    _flood_stderr()
    anyio.run(main)
