#!/usr/bin/env python3
"""Print the ``Secrets from files`` variable table for docs/environment.md."""

from __future__ import annotations

from keystone_mcp.config import SECRET_VARIABLES


def main() -> None:
    print("| Variable | Meaning |")
    print("|---|---|")
    for name in SECRET_VARIABLES:
        print(f"| `{name}_FILE` | reads `{name}` from a file |")


if __name__ == "__main__":
    main()
