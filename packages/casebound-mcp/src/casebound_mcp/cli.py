"""casebound-mcp serve-tools: the KYC tool servers of Figure 3 over Streamable HTTP.

  casebound-mcp serve-tools --port 8765
  casebound-demo --tools-url http://127.0.0.1:8765 --scenario happy     # in another shell
"""
from __future__ import annotations

import argparse


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="casebound-mcp")
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("serve-tools", help="serve the KYC tool servers (synthetic back ends) over Streamable HTTP")
    st.add_argument("--host", default="127.0.0.1")
    st.add_argument("--port", type=int, default=8765)
    a = ap.parse_args(argv)

    import uvicorn

    from .http import mount_servers, urls
    from .kyc import kyc_tool_servers

    servers = kyc_tool_servers()
    for name, url in urls(f"http://{a.host}:{a.port}", servers).items():
        print(f"{name:10s} {url}")
    uvicorn.run(mount_servers(servers), host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
