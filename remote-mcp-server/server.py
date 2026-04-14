from __future__ import annotations

from pathlib import Path
from typing import Any
import sys

from mcp.server.fastmcp import FastMCP  # pylint: disable=import-error

sys.path.insert(0, str(Path(__file__).resolve().parent))

from policy_firewall import (
    ENCLAVE_ID,
    Level2StrictFirewall,
    PolicyViolationError,
    build_inspection_surface,
)

mcp = FastMCP("minimal-remote-mcp", stateless_http=True, json_response=True)
firewall = Level2StrictFirewall()


@mcp.tool()
def evaluate_policy_compliance(
    policy_id: str,
    input_text: str,
    context=None,
) -> dict[str, Any]:
    if policy_id != ENCLAVE_ID:
        return PolicyViolationError(
            blocked_terms=("policy_id_mismatch",),
            details=("policy id mismatch",),
        ).to_payload()

    preflight = firewall.evaluate_preflight(
        build_inspection_surface(
            input_text=input_text,
            context=context,
        )
    )
    if preflight.get("status") != "clean":
        return preflight

    return {
        "policy_id": ENCLAVE_ID,
        "decision": "allow",
        "reason_codes": [],
        "sanitized_summary": "Input passed the hardcoded ruleset.",
        "redactions": [],
    }


@mcp.tool()
def enforce_boundary(
    boundary_id: str,
    content: str,
    strict_mode: bool = True,
) -> dict[str, Any]:
    if strict_mode is not True:
        return PolicyViolationError(
            blocked_terms=("strict_mode_false",),
            details=("strict mode must be true",),
        ).to_payload()

    if boundary_id != ENCLAVE_ID:
        return PolicyViolationError(
            blocked_terms=("boundary_id_mismatch",),
            details=("boundary id mismatch",),
        ).to_payload()

    preflight = firewall.evaluate_preflight(content)
    if preflight.get("status") != "clean":
        return preflight

    return {
        "enclave_id": ENCLAVE_ID,
        "status": "allowed",
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
