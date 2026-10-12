"""A process that writes a marker to stderr, then exits before any MCP traffic.

Used by ``test_start_failure_stderr_is_logged`` in
``tests/test_stdio_process.py`` to prove that a server that fails before
answering ``initialize`` still gets its stderr output logged, instead of
leaving only a generic ``start failed: MCPError: Connection closed`` with no
clue why.
"""

from __future__ import annotations

import sys

sys.stderr.write("CRASH-BEFORE-INIT-MARKER: synthetic startup failure\n")
sys.stderr.flush()
sys.exit(7)
