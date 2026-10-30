"""Entry point: `python -m arcanum_mcp` (stdio transport, local only)."""
from __future__ import annotations

from .server import build_server


def main() -> None:
    server = build_server()
    try:
        server.run(transport="stdio")
    except TypeError:  # mcp<2 FastMCP.run() has no transport argument
        server.run()


if __name__ == "__main__":
    main()