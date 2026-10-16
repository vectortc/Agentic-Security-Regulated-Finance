"""Serve several MCP servers over Streamable HTTP from one process: `/<name>/mcp` each.

Starlette does not run a mounted app's lifespan, and each MCP server's lifespan starts its session
manager, so the parent app runs them all.
"""
from __future__ import annotations

import contextlib
import threading
import time
from typing import Iterator, Mapping

from mcp.server import MCPServer
from starlette.applications import Starlette
from starlette.routing import Mount


def mount_servers(servers: Mapping[str, MCPServer]) -> Starlette:
    apps = {name: s.streamable_http_app(streamable_http_path="/mcp") for name, s in servers.items()}

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with contextlib.AsyncExitStack() as stack:
            for app in apps.values():
                await stack.enter_async_context(app.router.lifespan_context(app))
            yield

    return Starlette(routes=[Mount(f"/{name}", app=app) for name, app in apps.items()], lifespan=lifespan)


def urls(base: str, names) -> dict[str, str]:
    return {name: f"{base.rstrip('/')}/{name}/mcp" for name in names}


@contextlib.contextmanager
def serve_in_thread(servers: Mapping[str, MCPServer], host: str = "127.0.0.1", port: int = 0) -> Iterator[str]:
    """Run `servers` on a background uvicorn; yields the base URL. For tests and the demo."""
    import uvicorn

    config = uvicorn.Config(mount_servers(servers), host=host, port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("MCP HTTP server did not start")
        time.sleep(0.02)
    bound = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://{host}:{bound}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
