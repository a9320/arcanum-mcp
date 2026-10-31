"""Entry point: `python -m arcanum_mcp` (stdio) 或 `--http`（远程形态，必须带 token）。"""
from __future__ import annotations

import sys

from .server import build_server, run_http


def main() -> None:
    server = build_server()
    args = sys.argv[1:]
    if "--http" in args:
        host = args[args.index("--host") + 1] if "--host" in args else "127.0.0.1"
        port = int(args[args.index("--port") + 1]) if "--port" in args else 8000
        run_http(server, host=host, port=port)
        return
    try:
        server.run(transport="stdio")
    except TypeError:  # mcp<2 FastMCP.run() has no transport argument
        server.run()


if __name__ == "__main__":
    main()