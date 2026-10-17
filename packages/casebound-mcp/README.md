# casebound-mcp

MCP tooling for `casebound`: the case-bound tool contract, tool servers, a client adapter, and the
gateway. It lives outside the stdlib-only core; the core reaches it only through the `ToolAdapter`
port.

```
agent (any MCP client) --MCP--> gateway --Algorithm 2--> McpToolAdapter --MCP--> tool servers
casebound workflow (Alg 1) -----------> Algorithm 2 ---> McpToolAdapter --MCP--> tool servers
```

| Module | What it is |
|---|---|
| `contract` | What a tool must accept and echo: a mandatory `case_id` (validated by the protocol, before the tool runs), Algorithm 2's provenance envelope, and a response tagged with the case and attempt (Sections 5.3 and 7.2 of the paper). |
| `tool_server` | Serves an in-process `ToolRegistry` as an MCP server that meets the contract. |
| `client` | `McpToolAdapter`, the `casebound.ToolAdapter` port over MCP. |
| `gateway` | Casebound as an MCP server. `case_id` is mandatory and must name an open case. C2 uses the gateway's configured role and the case's workflow; C3 uses the case's recorded policy; C4 scans the whole payload. Every call is recorded as `TOOL_INVOKED`/`TOOL_COMPLETED`, and every refusal as the denial event. |
| `kyc` | The KYC tools of Section 5.1 as separate servers: identity, bureau, ACH, plus `accounts` (a capability no KYC role holds). Policy lookup is Algorithm 3, not a tool call. |

```bash
casebound-demo --tools mcp --scenario happy          # every tool call over MCP, in process
casebound-mcp serve-tools --port 8765                 # tool servers over Streamable HTTP
casebound-demo --tools-url http://127.0.0.1:8765      # ... and the workflow reaching them
cd packages/casebound-mcp && PYTHONPATH=../casebound pytest -q
```

The back ends are synthetic. They answer from the scenario's fixture, which travels in the
contract's `context` argument, and a real tool ignores it.
