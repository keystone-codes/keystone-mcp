"""A stdio MCP upstream that writes one over-limit stderr line, then serves MCP.

Used by ``test_oversized_stderr_line_does_not_crash_supervisor`` in
``tests/test_stdio_process.py`` to prove that
``StdioUpstreamProcess._read_stderr_until_eof`` survives
``asyncio.StreamReader.readline()`` raising ``ValueError`` for a line longer
than its buffer limit with no newline in sight, instead of letting that
exception kill (and misleadingly restart) an otherwise healthy process.

Serves the same tools as ``stdio_upstream.py`` (imported, not duplicated)
once the oversized line is written.
"""

from __future__ import annotations

import sys

import anyio
from stdio_upstream import main

#: Bigger than _STDERR_READER_LIMIT (1 MiB) in keystone_mcp.router.stdio_process.
_GIANT_BYTES = 2 * 1024 * 1024


def _write_giant_line() -> None:
    sys.stderr.write("y" * _GIANT_BYTES)
    sys.stderr.write("\n")
    sys.stderr.flush()


if __name__ == "__main__":
    _write_giant_line()
    anyio.run(main)
