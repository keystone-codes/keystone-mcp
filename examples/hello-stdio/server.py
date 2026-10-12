"""Minimal stdio MCP server listing and reading files in ./notes."""

from __future__ import annotations

from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES_DIR = Path(__file__).resolve().parent / "notes"


@mcp.tool()
def list() -> list[str]:
    """Return note file names in the notes directory."""
    return sorted(p.name for p in NOTES_DIR.iterdir() if p.is_file())


@mcp.tool()
def read(name: str) -> str:
    """Read one note by name (no path components allowed)."""
    if "/" in name or name.startswith(".") or ".." in name:
        raise ValueError("invalid name")
    path = NOTES_DIR / name
    if not path.is_file():
        raise FileNotFoundError(name)
    return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run(transport="stdio")
