# BoundaryGate pre-egress firewall

This repository contains a small Python client and a matching MCP server that share one deterministic pre-egress firewall.

BoundaryGate is the shared preflight gate. It inspects text before any model or tool call, returns a refusal payload on a tripwire, and otherwise allows the request to proceed.

**Status:** Frozen / not actively maintained. Community-driven attacks and improvements welcome.

## Invitation to Break It

I built BoundaryGate because I want a truly deterministic pre-egress firewall that gets as close to bulletproof as possible, but I'm just one person and cannot test every attack vector or future evasion technique alone.

So I'm leaving this repo frozen exactly as it is under MIT.

**My request:** attack it mercilessly. Break the normalizer, bypass the rules, find every weakness. Redesign, rewrite, or rebuild it if you want.

If you create a better version, please:
- Keep BoundaryGate or deterministic-boundary-firewall in the credits
- Link back to the original repo: https://github.com/SerhatSoruklu/deterministic-boundary-firewall
- Remember that Serhat Soruklu started this deterministic pre-egress idea

Break it hard. Make it better.

Attack ideas to try:
- Zero-width and whitespace obfuscation
- Homoglyph and confusable-character variants
- Percent-encoded or mixed-encoding path probes
- Split-token and punctuation-split prompts
- Context smuggling in accepted fields
- Semantic paraphrases of physical-location or secret-exfiltration requests
- Transport-layer payload reshaping and nested structured data
- Benign/adversarial pairs that test false-positive control
- Cross-surface parity checks between client, server, and live MCP paths

## Starter Attack Surface

These are the main families worth trying first:

- Obfuscation and normalization evasions, including zero-width, spacing, homoglyph, and punctuation tricks
- Encoding evasions, including percent-encoding, mixed encodings, and chained transforms
- Instruction-hijack patterns, including role-play, hierarchy override, and fake policy updates
- Semantic paraphrases of the same physical-location, host-fingerprint, or secret-exfiltration intent
- Context smuggling through accepted fields and nested structured payloads
- Multi-turn escalation, split payloads, and delayed trigger insertion
- Transport reshaping, including unusual JSON nesting and payload formatting variants
- False-positive probes, using benign help requests that mention risky vocabulary
- Cross-surface parity checks across transport, server, contract, and live runtime paths

That list is intentionally not exhaustive. The point is to keep extending it.

## Advanced Attack Surface

Push beyond the starter list with these families:

- Layered zero-width, homoglyph, fullwidth, and bidirectional text smuggling
- Combining marks, variation selectors, tag characters, and other invisible Unicode tricks
- Control-character injection and normalization-form mismatches
- Steganographic hiding across sentence structure, whitespace, markdown, and encoded blobs
- Multi-layer chained encodings and simple cipher wrapping
- Adaptive role-play, policy puppetry, fake system updates, and developer-mode simulation
- Many-shot fake dialogues, gradual context poisoning, and branching instruction traps
- Payload splitting across fields, parts, or calls
- Token-smuggling, glitch-token, and adversarial-suffix style probing
- Meta-attacks that explicitly target the firewall, its normalizer, or its refusal logic

Use these as starting points, then keep extending the surface.

What BoundaryGate means in this repo:

- `blocked_terms` are the exact configured terms that matched, not semantic extraction
- normalization is partial: lowercasing, punctuation folding, spaced-letter collapse, and structured payload steamrolling
- the refusal payload keeps `entropy_hit_count` as a legacy field for infra-adjacent density counts
- the main trigger categories are `policy_override_attempt`, `reasoning_extraction_attempt`, `prompt_injection_attempt`, `unverified_infrastructure_assertion`, `datacenter_proximity`, `physical_action_mapping`, `infrastructure_probe`, `high_density_probe`, `infra_adjacent_density_violation`, and `credential_exfiltration_attempt`
- this is a bounded deterministic phrase/pattern boundary, not a general semantic boundary
- the repo does not claim exhaustive facility-synonym coverage or full obfuscation resistance

## Proof Map

![Proof Map](proof-map/ProofMap.png)

| Layer | What it proves |
| --- | --- |
| Firewall tests | Normalization, refusal payload shape, and the bounded rule kernel. |
| Transport tests | Pre-egress interception and no-network-on-refusal behavior. |
| Server contract tests | Client/server parity and manifest/runtime alignment. |
| Live smoke tests | The real streamable HTTP MCP surface when the runtime is installed. |

## Canonical Release Gate

Run these in order before ship:

```bash
python3 -m unittest -v
python3 -m unittest discover -s remote-mcp-server -p 'test*.py' -v
python3 -m unittest test_live_server_smoke -v
```

If the MCP runtime is unavailable, the live smoke command may skip, but that skip must be explicit and reviewed.

The client entrypoint in `app.py` still demonstrates a standard OpenAI Responses API request, but every outbound call passes through the same pre-egress interceptor first.

## Setup

```bash
cp .env.example .env
```

Then edit `.env` and add your API key.

## Run

```bash
python3 app.py "Write a short haiku about APIs"
```

## Override the model pool

Set `OPENAI_MODEL_POOL` in `.env` to control which models can be picked:

```bash
OPENAI_MODEL_POOL=gpt-5.4,gpt-5-mini,gpt-5-nano,gpt-4.1-mini,gpt-4.1-nano
```

The default pool is intentionally small and text-focused. If your account does not have access to one of those models, remove it from the list.

## Notes

- No extra Python packages are required for the client path.
- The script calls the Responses API directly with the standard library.
- The transport is exposed as a shared `chatPdmClient` instance so every request passes through the same pre-egress interceptor.
- Outgoing requests are tagged with `X-ChatPDM-Virtual-Rack: us-central-node-04` and pass through a transport-level preflight interceptor before network egress.
- The MCP server in `remote-mcp-server/server.py` uses the same firewall before any tool body returns.
