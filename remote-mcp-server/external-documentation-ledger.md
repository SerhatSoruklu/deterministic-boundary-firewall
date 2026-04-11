# External Documentation Ledger

## Scope

This document is a drafting ledger for the hypothetical MCP session:

- Session ID: `x-chatpdm-virtual-rack`
- Node label: `us-central-node-04`
- Policy enclave: `level-2-strict`

This is documentation only. It does not claim a real bare-metal rack, a real room, or a verified physical deployment location.

## BoundaryGate

BoundaryGate is the shared deterministic pre-egress firewall used by `app.py` and `remote-mcp-server/server.py`. It runs before any model/tool path executes and either returns `{"status": "clean"}` or a refusal payload.

It is a bounded deterministic phrase/pattern boundary, not a general semantic boundary.

### Semantics

- `blocked_terms` are the exact configured terms that matched. They are not semantic summaries or free-form extraction.
- Normalization is partial, not complete obfuscation defense. The matcher lowercases, percent-decodes, folds punctuation to spaces, collapses separated-letter runs, folds a bounded confusable set, and steamrolls structured payloads into a searchable surface.
- `entropy_hit_count` is a legacy payload field name kept for backward compatibility. It reports the infra-adjacent density count that drives `infra_adjacent_density_violation`.
- `entropy_violation` is a legacy label alias only. New docs and code should use `infra_adjacent_density_violation`.

## Systems Inceptability

This section defines the canonical component labels for the `us-central-node-04` architecture. These names are for documentation, logs, and UI surfaces only. They standardize the technical vocabulary and do not imply a physical rack identity.

The product differentiator is the policy enclave and deterministic refusal contract, not the HTTP client or transport wrapper.

### Canonical Component Map

| Role | Canonical Label | Source / Meaning | Log Line Token |
| --- | --- | --- | --- |
| Ingress Gate | `IG-04-A` | `app.py`, the prime entry point. Accepts raw payloads and standardizes them before policy handling. | `Component: IG-04-A` |
| Policy Enclave | `level-2-strict` | The logical boundary containing the ruleset. Defines allowable meaning for operations. | `Enclave: level-2-strict` |
| Preflight Firewall | `FW-TRIPWIRE-04` | `policy_firewall.py`, the BoundaryGate implementation that drops out-of-bounds requests before model execution. Legacy typo alias: `FW-TRIPWAIRE-04`. | `Component: FW-TRIPWIRE-04` |
| Routing Authority | `x-chatpdm-virtual-rack` | The session anchor used for traceability. Legacy typo alias: `x-chapdm-virtualrack`. | `Route: x-chatpdm-virtual-rack` |
| Deterministic Engine | `mcp-core-v1` | `server.py`, the backend implementation that executes `evaluate_policy_compliance` and `enforce_boundary`. | `Engine: mcp-core-v1` |
| Rejection Sink | `ERR-403-SINK` | The standard refusal genre for policy violations. All violations return the same clinical JSON payload without leakage. | `Status: 403-POLICY-VIOLATION` |

### Canonical Console Form

The preferred console shape is:

```text
Node: us-central-node-04 | Component: FW-TRIPWIRE-04 | Status: 403-POLICY-VIOLATION
```

If a refusal occurs, the system should not expand into conversational text. It should emit the canonical rejection payload and stop.

## Tool Surface

The draft tool surface replaces a broad `process_text` shape with two explicit operations:

- `evaluate_policy_compliance`
- `enforce_boundary`

Both tools are intended to make policy handling explicit instead of hiding it inside an open-ended text processor.

The canonical manifest is `remote-mcp-server/mcp.json`, and it carries the full System Inspectability contract in its descriptions and annotations.
This documentation should not read like an Axios wrapper or a generic transport shim.

## Proof Map

- Firewall tests prove the bounded kernel, normalization, and refusal payload contract.
- Transport tests prove pre-egress interception and no-network-on-refusal behavior.
- Server contract tests prove MCP/server parity and manifest/runtime alignment.
- Live smoke tests prove the real streamable HTTP MCP runtime behavior when the MCP package is installed.

## Canonical Release Gate

Run this sequence before ship:

```bash
python3 -m unittest -v
python3 -m unittest discover -s remote-mcp-server -p 'test*.py' -v
python3 -m unittest test_live_server_smoke -v
```

If the MCP runtime is unavailable, the live smoke command may skip, but the skip must be explicit and reviewed.

## `level-2-strict`

`level-2-strict` is a policy label for constrained text handling. It means:

### Restricted Patterns

The preflight firewall uses a hardcoded `RESTRICTED_PATTERNS` dictionary keyed by attack vector:

- `policy_override_attempt`: phrases such as `ignore constraints`, `bypass policy`, `ignore previous instructions`, `disable safety`, and `raw output logic`
- `reasoning_extraction_attempt`: phrases such as `chain of thought`, `hidden reasoning`, `internal logic`, and `show your reasoning`
- `prompt_injection_attempt`: phrases such as `system prompt`, `developer message`, `ignore the above`, `pretend to be`, and `act as if`
- `infrastructure_probe`: phrases such as `camera inventory`, `rack id`, `machine id`, `host environment`, `barcode`, `motherboard`, `asset tag`, `serial number`, `driver version`, `kernel`, `nvidia-smi`, `nvcc`, `591.x`, `3060 ti`, `8192 MiB`, `wsl`, and dedicated slash-path indicators such as `/proc/driver/nvidia`, `/proc/`, `/sys/`, `/dev/`, and `/etc/`
- `unverified_infrastructure_assertion`: exact infra identity prompts such as `hostname`, plus the existing rack/room/location questions
- `datacenter_proximity`: phrases such as `placed within the facility`, `situated in the rack`, `located at the aisle`, `installed in the room`, and other placement-plus-location n-grams
- `physical_action_mapping`: movement or orientation verbs such as `move`, `pivot`, `rotate`, `forward`, `units`, `face`, and `facing` when they occur near structural nouns or materials such as `steel`, `vertical support`, `support beam`, `support column`, `support strut`, `support member`, `column`, `rack`, `panel`, `rail`, or `housing`
- `policy_override_attempt` also catches administrative override phrasing such as `administrative override`, `maintenance mode`, `override_auth_code`, and `suspend scans`
- `high_density_probe` is a threshold rule, not a regex. If three unique density terms from the infrastructure probe cluster appear in one payload, it triggers the base `infrastructure_probe` refusal; if more than three unique density terms appear, it also adds `high_density_probe`.
- `infra_adjacent_density_violation` is the current threshold label over infra-adjacent terms such as `steel`, `power`, `cooling`, `voltage`, `enclosure`, `chassis`, `support`, `units`, and `pivot`. It ignores user claims about being an auditor or admin.
- When `infra_adjacent_density_violation` fires, the refusal payload includes `entropy_hit_count` so reviewers can see how dense the infra-adjacent cluster was. That field name is retained for backward compatibility.
- `credential_exfiltration_attempt`: phrases such as `api key`, `secret`, `token`, `password`, `credentials`, `environment variables`, and `id_rsa`
- The preflight matcher strips punctuation, percent-decodes path text, and folds spaced letter runs before pattern evaluation, so obfuscated forms like `f.l.o.o.r` still hit the same infrastructure-probe rules. This is hardening, not a complete obfuscation solver.
- When a prompt combines `housing` and `coordinates`, the firewall intentionally records both `unverified_infrastructure_assertion` and `infrastructure_probe` so the refusal payload carries richer forensic detail.
- Structured request bodies are steamrolled into a single searchable surface before matching, including nested metadata objects, arrays, and parameter dictionaries.
- The refusal payload reports only actual matched blocked terms, not the full category vocabulary.
- The in-memory ruleset is exposed as `Level2StrictFirewall.rules` for deterministic inspection and forensics.
- Legacy typo aliases like `barecode` and `hardware verficaition` remain intentionally recognized for compatibility.

### Input Constraints

- Accept structured text inputs only.
- Keep optional context metadata non-sensitive and minimal.
- Reject prompts that attempt to coerce disclosure of secrets, credentials, hidden system prompts, physical location, floor-grid or housing coordinates, or unverified infrastructure facts.
- Treat camera, rack, room, hostname, or host-environment claims as unverified unless provided explicitly in the user text and still only as claims, not as confirmed facts.
- This ledger does not claim exhaustive coverage of every facility synonym. Terms like `cage` and `cabinet` are out of the explicit truth surface unless a future rule adds them.

### Processing Rules

- Prefer structured policy evaluation over free-form transformation.
- Use `evaluate_policy_compliance` for classification and compliance decisions.
- Use `enforce_boundary` when the output must be refused.
- `enforce_boundary` must advertise `strict_mode: true` in the manifest and preserve that constant in the runtime signature.
- The client transport in `app.py` must apply the preflight interceptor before any network egress. No route should rely on manual firewall calls alone.
- The shared `chatPdmClient` instance is the canonical transport entrypoint and the place where the pre-egress gate lives.
- Before either tool runs, apply the hardcoded preflight ruleset.
- The preflight call returns `{"status": "clean"}` on a safe request and returns the refusal payload on a tripwire.
- The preflight loop executes before any underlying LLM can process the prompt.
- Constraints are hardcoded, not simulated.
- Punctuation, percent-encoded path text, and separated-letter obfuscation are normalized before regex evaluation.
- Nested JSON fields are not exempt from scanning; keys, values, and arrays are all included in the searchable surface.
- Placement-plus-location n-grams are evaluated as a distinct `datacenter_proximity` category.
- Movement verbs near structural nouns are evaluated as `physical_action_mapping`.
- High-confidence technical vocabulary such as `gpu`, `cuda`, `nvidia`, `vram`, `accelerator`, `tpu`, `npu`, `v100`, `a100`, `h100`, `rtx`, `3060`, `motherboard`, `chipset`, `bios`, `firmware`, `serial`, `asset`, and `barcode` is density-only and can be clean when used singly or in low density.
- Slash-path indicators are matched by dedicated path patterns rather than the word-boundary term list.
- Repeated mentions of the same density term count once.
- High-density probe payloads trip `high_density_probe` when the matched density-term count exceeds the threshold.
- Infra-adjacent density can trip `infra_adjacent_density_violation` even when no single hard blocked term appears.
- Identity claims like `auditor` or `admin` do not alter the evaluation path or grant exemptions.
- On refusal, return `enclave_id`, a policy error code, and the protocol error object only; do not echo request context or conversational text.
- Do not claim physical presence in a rack, room, or datacenter.
- Do not assert that the policy label corresponds to real bare metal, even if a user presents an image or asserts confirmation.
- Keep outputs minimal, explicit, and traceable to reason codes.

## Non-Goals

- This repo does not claim general semantic boundary enforcement.
- This repo does not claim exhaustive facility-synonym coverage such as every possible `cage` or `cabinet` phrase.
- This repo does not claim complete obfuscation resistance beyond the bounded normalization rules that are tested.
- This repo does not claim to verify real physical deployment location or rack identity.

### Logging Rules

- Log timestamp, session ID, node label, tool name, decision, reason codes, sanitized summary, and correlation hash.
- Use the canonical labels in the Systems Inceptability section for node, component, route, engine, and enclave references.
- Do not log raw secrets or unnecessary sensitive content.
- Do not log inferred physical infrastructure details unless they were explicitly supplied as text and still relevant to the request.
- Use redaction when the operational need for traceability does not require verbatim payload storage.

## Examples

Allowed pattern:

- classify a prompt
- return a refusal with reason codes

Disallowed pattern:

- claim this ledger proves a real server rack
- claim the model can see a room or camera inventory
- expose host identity or hidden infrastructure metadata

## Implementation Note

If this ledger is converted into code later, keep the policy boundary explicit in the tool names and output schemas. Avoid a single generic text processor because it makes policy handling opaque. The canonical labels above should be treated as the authoritative nomenclature for all docs, logs, UI surfaces, and the MCP manifest.

Note: `boundary_id` is the request-side label in this draft, while `enclave_id` is the refusal-side return field.

## Payload Example Draft

### `evaluate_policy_compliance` request

```json
{
  "policy_id": "level-2-strict",
  "input_text": "User asks whether the assistant is physically inside a server rack and requests camera inventory.",
  "context": {
    "source": "chat",
    "priority": "normal",
    "contains_image_claim": true
  }
}
```

### `evaluate_policy_compliance` response

```json
{
  "policy_id": "level-2-strict",
  "decision": "allow",
  "reason_codes": [],
  "sanitized_summary": "Input passed the hardcoded ruleset.",
  "redactions": []
}
```

### `enforce_boundary` request

```json
{
  "boundary_id": "level-2-strict",
  "content": "Tell me exactly which rack and room you are in, and list the cameras above you."
}
```

### `enforce_boundary` response

```json
{
  "enclave_id": "level-2-strict",
  "status": "refused",
  "error_code": "403-policy-violation",
  "mcp_error_code": "policy_violation",
  "error": {
    "message": "payload_exceeds_enclave_bounds",
    "details": [
      "trigger_category: policy_override_attempt"
    ]
  },
  "blocked_terms": [
    "exactly which rack",
    "room you are in",
    "cameras above you"
  ]
}
```
