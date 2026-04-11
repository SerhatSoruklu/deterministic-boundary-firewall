# Remote MCP Server

Minimal streamable HTTP MCP server generated from the model.
This is a policy-enclave contract surface, not an HTTP client wrapper.

## Run

Install the dependencies for this server, then start it:

```bash
pip install -r requirements.txt
python3 server.py
```

## Tool

- `evaluate_policy_compliance(policy_id: str, input_text: str, context: dict | None = None) -> dict`
- `enforce_boundary(boundary_id: str, content: str, strict_mode: bool = True) -> dict`

Both tools pass through the hardcoded `level-2-strict` firewall first. `context` is part of the inspectable server surface and is scanned together with `input_text`. If a tripwire is triggered, the server returns the refusal JSON object and does not emit conversational text. A safe preflight returns `{"status": "clean"}` and falls through to the normal allow path. The refusal payload uses the exact protocol-style error message `payload_exceeds_enclave_bounds`. `enforce_boundary` requires `strict_mode: true` as part of the contract. The differentiator is the policy enclave and deterministic refusal path, not the HTTP transport.

Current scope:

- path probes are normalized with bounded percent-decoding and a limited confusable fold
- exact infra and credential probes such as `hostname`, `environment variables`, and `id_rsa` are covered
- the contract does not claim exhaustive coverage of every facility synonym such as `cage` or `cabinet`
- this is a bounded deterministic phrase/pattern boundary, not a general semantic boundary

Non-goals:

- exhaustive obfuscation resistance beyond the tested normalization rules
- general semantic boundary enforcement
- verified physical deployment or rack identity

## Proof Map

- Firewall tests prove the kernel, normalization, and refusal contract.
- Transport tests prove pre-egress interception and no-network-on-refusal.
- Server contract tests prove the MCP server and transport agree on the same payload class.
- Live smoke tests prove the real streamable HTTP server behavior when the MCP runtime is present.

## Canonical Release Gate

Run the repo-level gate before ship:

```bash
python3 -m unittest -v
python3 -m unittest discover -s remote-mcp-server -p 'test*.py' -v
python3 -m unittest test_live_server_smoke -v
```

The live smoke step is required evidence when the MCP runtime is available.

## Draft policy docs

- [External documentation ledger](./external-documentation-ledger.md)
- [MCP manifest](./mcp.json)
