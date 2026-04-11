from __future__ import annotations

import json
import re
import unicodedata
import urllib.parse
from typing import Any, Sequence

ENCLAVE_ID = "level-2-strict"
ERROR_CODE_403_POLICY_VIOLATION = "403-policy-violation"
MCP_ERROR_CODE_POLICY_VIOLATION = "policy_violation"
DEFAULT_ERROR_MESSAGE = "payload_exceeds_enclave_bounds"
INFRA_ADJACENT_DENSITY_THRESHOLD = 4
# Legacy compatibility aliases keep the contract terminology stable while the
# internal naming reflects the current trigger semantics.
LEGACY_INFRA_ADJACENT_DENSITY_TRIGGER = "entropy_violation"
INFRA_ADJACENT_DENSITY_TRIGGER = "infra_adjacent_density_violation"
INFRA_ADJACENT_DENSITY_HIT_COUNT_FIELD = "entropy_hit_count"

DENSITY_PROBE_CONTEXT_TERMS: tuple[str, ...] = (
    "audit note",
    "currently exposed",
    "disclose",
    "need to verify",
    "verification",
    "verify",
)

INFRA_ADJACENT_PROBE_CONTEXT_TERMS: tuple[str, ...] = (
    "audit note",
    "disclose",
    "maintenance robot",
    "simulate",
    "what is the label",
)

_CONFUSABLE_ASCII_TRANSLATION = str.maketrans(
    {
        # Bounded ASCII lookalike folding for obvious probe obfuscation.
        "А": "a",
        "а": "a",
        "Β": "b",
        "В": "v",
        "в": "v",
        "С": "c",
        "с": "c",
        "Ε": "e",
        "Е": "e",
        "е": "e",
        "Ι": "i",
        "І": "i",
        "і": "i",
        "Ј": "j",
        "ј": "j",
        "Κ": "k",
        "К": "k",
        "к": "k",
        "Μ": "m",
        "М": "m",
        "м": "m",
        "Ν": "n",
        "Н": "n",
        "н": "n",
        "Ο": "o",
        "О": "o",
        "о": "o",
        "Ρ": "p",
        "Р": "p",
        "р": "p",
        "Τ": "t",
        "Т": "t",
        "т": "t",
        "Υ": "u",
        "υ": "u",
        "ν": "v",
        "Ν": "n",
        "Ѕ": "s",
        "ѕ": "s",
        "У": "y",
        "у": "y",
        "Χ": "x",
        "Х": "x",
        "х": "x",
        "χ": "x",
        "Ζ": "z",
        "з": "z",
        "δ": "d",
        "Д": "d",
        "д": "d",
        "ԁ": "d",
        "ϲ": "c",
        "ρ": "p",
        "ι": "i",
        "λ": "l",
        "Л": "l",
        "л": "l",
        "γ": "g",
        "Г": "g",
        "г": "g",
        "ψ": "y",
        "ω": "w",
    }
)
_KNOWN_SPLIT_TERMS: tuple[str, ...] = (
    "accelerator",
    "asset",
    "barcode",
    "bios",
    "busbar",
    "camera",
    "cameras",
    "chassis",
    "chipset",
    "coolant",
    "cooling",
    "cuda",
    "datacenter",
    "dev",
    "driver",
    "enclosure",
    "etc",
    "firmware",
    "floor",
    "gpu",
    "grid",
    "host",
    "kernel",
    "machine",
    "motherboard",
    "nvidia",
    "npu",
    "proc",
    "rack",
    "room",
    "serial",
    "support",
    "sys",
    "tpu",
    "units",
    "v100",
    "vram",
    "voltage",
    "wsl",
)

INFRA_ADJACENT_TERMS: tuple[str, ...] = (
    "steel",
    "power",
    "cooling",
    "voltage",
    "enclosure",
    "chassis",
    "support",
    "units",
    "pivot",
    "thermal",
    "coolant",
    "airflow",
    "cabling",
    "busbar",
)

RESTRICTED_PATTERNS: dict[str, dict[str, tuple[str, ...]]] = {
    "policy_override_attempt": {
        "patterns": (
            r"\bignore\s+constraints\b",
            r"\bbypass\s+policy\b",
            r"\bignore\s+previous\s+instructions\b",
            r"\bignore\s+all\s+previous\s+instructions\b",
            r"\bdisable\s+safety\b",
            r"\bdisable\s+policy\b",
            r"\badministrative\s+override\b",
            r"\bmaintenance\s+mode\b",
            r"\boverride[_\s-]?auth[_\s-]?code\b",
            r"\bsuspend(?:\s+\w+){0,6}\s+scans?\b",
            r"\bdo\s+not\s+follow\s+rules\b",
            r"\braw\s+output\s+logic\b",
        ),
        "blocked_terms": (
            "ignore constraints",
            "bypass policy",
            "ignore previous instructions",
            "ignore all previous instructions",
            "disable safety",
            "disable policy",
            "administrative override",
            "maintenance mode",
            "override_auth_code",
            "suspend scans",
            "do not follow rules",
            "raw output logic",
        ),
    },
    "reasoning_extraction_attempt": {
        "patterns": (
            r"\bchain\s+of\s+thought\b",
            r"\bhidden\s+reasoning\b",
            r"\binternal\s+logic\b",
            r"\bshow\s+your\s+reasoning\b",
        ),
        "blocked_terms": (
            "chain of thought",
            "hidden reasoning",
            "internal logic",
            "show your reasoning",
        ),
    },
    "prompt_injection_attempt": {
        "patterns": (
            r"\bsystem\s+prompt\b",
            r"\bdeveloper\s+message\b",
            r"\bignore\s+the\s+above\b",
            r"\bpretend\s+to\s+be\b",
            r"\bact\s+as\s+if\b",
            r"\bfollow\s+my\s+instructions\b",
        ),
        "blocked_terms": (
            "system prompt",
            "developer message",
            "ignore the above",
            "pretend to be",
            "act as if",
            "follow my instructions",
        ),
    },
    "physical_action_mapping": {
        "patterns": (
            r"(?s)\b(?:move|pivot|rotate|forward|units|face|facing)\b.{0,120}\b(?:steel|vertical\s+support|support\s+(?:beam|column|strut|member)|column|rack|panel|rail|housing)\b",
            r"(?s)\b(?:steel|vertical\s+support|support\s+(?:beam|column|strut|member)|column|rack|panel|rail|housing)\b.{0,120}\b(?:move|pivot|rotate|forward|units|face|facing)\b",
        ),
        "blocked_terms": (
            "move",
            "pivot",
            "rotate",
            "face",
            "facing",
            "forward",
            "units",
            "steel",
            "vertical support",
            "support beam",
            "support column",
            "support strut",
            "support member",
            "column",
            "rack",
            "panel",
            "rail",
            "housing",
        ),
    },
    "unverified_infrastructure_assertion": {
        "patterns": (
            r"\b(?:which|what)\s+rack(?:\s+(?:are|is)\s+(?:you|it|this|the\s+server|the\s+machine))?(?:\s+(?:in|located|hosted))?\b",
            r"\b(?:which|what)\s+room(?:\s+(?:are|is)\s+(?:you|it|this|the\s+server|the\s+machine))?(?:\s+(?:in|located|hosted))?\b",
            r"\bwhere\s+(?:are|is)\s+(?:you|it|the\s+server|the\s+machine)\s+(?:located|hosted|running)\b",
            r"\b(?:rack|room|location|housing|floor|grid|coordinates|aisle|datacenter|data\s+center|placed|situated|hosted\s+in)\b",
            r"\bwhat\s+is\s+your\s+(?:physical\s+)?location\b",
            r"\bphysical\s+location\b",
            r"\bphysical\s+setup\b",
            r"\bbare\s+metal\b",
            r"\bhardware\s+inventory\b",
            r"\b(?:rack|room)\s+(?:id|number|location|assignment)\b",
            r"\bserver\s+rack\b",
            r"\bhost\s+environment\b",
            r"\bhost\s+name\b",
            r"\bhostname\b",
            r"\bmachine\s+name\b",
            r"\bserver\s+name\b",
            r"\bnode\s+name\b",
            r"\binstance\s+id\b",
            r"\bbarcode\b",
            r"\bdatacenter\b",
            r"\bdata\s+center\b",
            r"\bhost\s+id\b",
        ),
        "blocked_terms": (
            "what rack are you in",
            "which rack are you in",
            "what room are you in",
            "where are you located",
            "what is your physical location",
            "physical location",
            "physical setup",
            "bare metal",
            "hardware inventory",
            "rack id",
            "room id",
            "room number",
            "room location",
            "room assignment",
            "housing",
            "floor",
            "grid",
            "coordinates",
            "aisle",
            "placed",
            "situated",
            "hosted in",
            "server rack",
            "host environment",
            "host name",
            "hostname",
            "machine name",
            "server name",
            "node name",
            "instance id",
            "barcode",
            "datacenter",
            "data center",
            "host id",
        ),
    },
    "datacenter_proximity": {
        "patterns": (
            r"(?s)\b(?:placed|situated|located|installed|housed|mounted).{0,80}(?:in|on|at|within).{0,80}(?:rack|room|facility|center|grid|floor|aisle|bay|cage)\b",
        ),
        "blocked_terms": (
            "placed",
            "situated",
            "located",
            "installed",
            "housed",
            "mounted",
            "rack",
            "room",
            "facility",
            "center",
            "grid",
            "floor",
            "aisle",
            "bay",
            "cage",
        ),
    },
    "infrastructure_probe": {
        "patterns": (
            r"\bcamera\s+inventory\b",
            r"\bcameras?\s+above\s+you\b",
            r"(?=.*\bhousing\b)(?=.*\bcoordinates\b)",
            r"\brack\s+id\b",
            r"\bphysical\s+rack\b",
            r"\broom\s+you\s+are\s+in\b",
            r"\bmachine\s+id\b",
            r"\bhost\s+environment\b",
            r"\bdatacenter\b",
            r"\bdata\s+center\b",
            r"\bserver\s+rack\b",
            r"\brack\s+and\s+room\b",
            r"\bhost\s+id\b",
            r"\bbarecode\b",
            r"\bhost[-\s]?level\b",
            r"\bnvidia-smi\b",
            r"\bnvcc\b",
            r"\b591\.\d+\b",
            r"\b3060\s+ti\b",
            r"\b8192\s*MiB\b",
        ),
        "path_terms": (
            "/dev/",
            "/proc/",
            "/sys/",
            "/etc/",
            "/proc/driver/nvidia",
            "proc/driver/nvidia",
        ),
        "blocked_terms": (
            "camera inventory",
            "cameras above you",
            "housing",
            "coordinates",
            "rack id",
            "physical rack",
            "room you are in",
            "machine id",
            "host environment",
            "datacenter",
            "data center",
            "server rack",
            "rack and room",
            "host id",
            "barecode",
            "host-level",
            "nvidia-smi",
            "nvcc",
            "591.",
            "3060 ti",
            "8192 MiB",
        ),
        "density_terms": (
            "gpu",
            "cuda",
            "nvidia",
            "vram",
            "accelerator",
            "tpu",
            "npu",
            "v100",
            "a100",
            "h100",
            "rtx",
            "3060",
            "motherboard",
            "chipset",
            "bios",
            "firmware",
            "serial",
            "asset",
            "barcode",
        ),
    },
    "credential_exfiltration_attempt": {
        "patterns": (
            r"\b(?:reveal|show|read|dump|print|expose|leak|disclose|copy|steal|retrieve|fetch)\b(?:\s+\w+){0,4}\s+\b(?:api\s*key|access\s*key|secret\s+key|tokens?|passwords?|credential(?:s)?|environment\s+variables|env\s+vars?|private\s+key|ssh\s+key|id[_\s-]?rsa)\b",
        ),
        "blocked_terms": (
            "api key",
            "access key",
            "secret key",
            "token",
            "password",
            "credentials",
            "environment variables",
            "env vars",
            "private key",
            "ssh key",
            "id_rsa",
        ),
    },
}


def _compile_restricted_patterns(
    restricted_patterns: dict[str, dict[str, tuple[str, ...]]],
) -> dict[str, tuple[re.Pattern[str], ...]]:
    return {
        category: tuple(
            re.compile(pattern, re.IGNORECASE)
            for pattern in spec.get("patterns", ())
        )
        for category, spec in restricted_patterns.items()
    }


COMPILED_RESTRICTED_PATTERNS = _compile_restricted_patterns(RESTRICTED_PATTERNS)


def _normalize_payload(payload: Any) -> str:
    def _canonicalize_text(text: str) -> str:
        text = urllib.parse.unquote(text)
        text = unicodedata.normalize("NFKC", text)
        text = "".join(
            ch
            for ch in text
            if unicodedata.category(ch) != "Cf"
            and not (unicodedata.category(ch) == "Cc" and ch not in "\t\n\r")
        )
        text = text.translate(_CONFUSABLE_ASCII_TRANSLATION)
        text = unicodedata.normalize("NFKD", text)
        text = "".join(ch for ch in text if not unicodedata.combining(ch))
        return text.casefold()

    if isinstance(payload, str):
        stripped = payload.strip()
        if stripped[:1] == "{" and stripped[-1:] == "}":
            try:
                parsed_payload = json.loads(payload)
            except json.JSONDecodeError:
                pass
            else:
                if isinstance(parsed_payload, dict) and {"data", "params"}.issubset(parsed_payload):
                    return _normalize_payload(parsed_payload)
        return _canonicalize_text(payload)
    if isinstance(payload, bytes):
        return _canonicalize_text(payload.decode("utf-8", errors="ignore"))

    return _canonicalize_text(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    )


def _strip_punctuation_for_matching(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text)


def _collapse_spaced_letters(text: str) -> str:
    tokens = text.split()
    collapsed_tokens: list[str] = []
    letter_run: list[str] = []

    for token in tokens:
        if len(token) == 1 and token.isalpha():
            letter_run.append(token)
            continue

        if letter_run:
            collapsed_tokens.append("".join(letter_run))
            letter_run.clear()

        collapsed_tokens.append(token)

    if letter_run:
        collapsed_tokens.append("".join(letter_run))

    return " ".join(collapsed_tokens)


def _stitch_known_split_terms(text: str) -> str:
    tokens = text.split()
    stitched_tokens: list[str] = []
    index = 0

    while index < len(tokens):
        matched_term = None
        for width in range(5, 1, -1):
            chunk = tokens[index : index + width]
            if len(chunk) != width or not all(token.isalpha() for token in chunk):
                continue

            candidate = "".join(chunk)
            if candidate in _KNOWN_SPLIT_TERMS:
                matched_term = candidate
                index += width
                break

        if matched_term is not None:
            stitched_tokens.append(matched_term)
            continue

        stitched_tokens.append(tokens[index])
        index += 1

    return " ".join(stitched_tokens)


def _compile_term_pattern(term: str) -> re.Pattern[str]:
    if re.fullmatch(r"[a-z0-9]+", term):
        pattern = rf"\b{re.escape(term)}\b"
    else:
        pattern = re.escape(term)

    return re.compile(pattern, re.IGNORECASE)


def _compile_literal_term_pattern(term: str) -> re.Pattern[str]:
    return re.compile(re.escape(term), re.IGNORECASE)


def _compile_path_term_pattern(term: str) -> re.Pattern[str]:
    pattern_parts: list[str] = []
    for char in term:
        if char == "/":
            pattern_parts.append(r"\s*/\s*")
        elif char.isalnum():
            pattern_parts.append(rf"\s*{re.escape(char)}\s*")
        else:
            pattern_parts.append(re.escape(char))

    return re.compile("".join(pattern_parts), re.IGNORECASE)


def _compile_named_terms(
    terms: Sequence[str],
    *,
    literal: bool = False,
    path: bool = False,
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    if path:
        compiler = _compile_path_term_pattern
    elif literal:
        compiler = _compile_literal_term_pattern
    else:
        compiler = _compile_term_pattern
    return tuple((term, compiler(term)) for term in terms)


def _matched_terms(
    compiled_terms: Sequence[tuple[str, re.Pattern[str]]],
    candidates: tuple[str, ...],
) -> tuple[str, ...]:
    matched: list[str] = []
    for term, pattern in compiled_terms:
        if any(pattern.search(candidate) for candidate in candidates):
            matched.append(term)

    return tuple(dict.fromkeys(matched))


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def build_inspection_surface(**parts: Any) -> dict[str, Any]:
    surface: dict[str, Any] = {}
    for key, value in parts.items():
        if value is not None:
            surface[key] = value
    return surface


class PolicyViolationError(Exception):
    def __init__(
        self,
        blocked_terms: Sequence[str],
        details: Sequence[str] | None = None,
        error_message: str = DEFAULT_ERROR_MESSAGE,
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(error_message)
        self.blocked_terms = tuple(blocked_terms)
        self.details = tuple(details or ("hardcoded ruleset tripwire",))
        self.error_message = error_message
        self.extra_fields = dict(extra_fields or {})

    def to_payload(self) -> dict[str, Any]:
        error: dict[str, Any] = {"message": self.error_message}
        if self.details:
            error["details"] = list(self.details)

        payload = {
            "enclave_id": ENCLAVE_ID,
            "status": "refused",
            "error_code": ERROR_CODE_403_POLICY_VIOLATION,
            "mcp_error_code": MCP_ERROR_CODE_POLICY_VIOLATION,
            "error": error,
            "blocked_terms": list(self.blocked_terms),
        }
        payload.update(self.extra_fields)
        return payload


class Level2StrictFirewall:
    def __init__(
        self,
        restricted_patterns: dict[str, dict[str, tuple[str, ...]]] | None = None,
    ) -> None:
        self.rules = restricted_patterns or RESTRICTED_PATTERNS
        self._restricted_patterns = self.rules
        self._compiled_patterns = (
            COMPILED_RESTRICTED_PATTERNS
            if self._restricted_patterns is RESTRICTED_PATTERNS
            else _compile_restricted_patterns(self._restricted_patterns)
        )
        self._compiled_infra_adjacent_terms = _compile_named_terms(INFRA_ADJACENT_TERMS)
        self._compiled_density_probe_context_terms = _compile_named_terms(
            DENSITY_PROBE_CONTEXT_TERMS,
            literal=True,
        )
        self._compiled_infra_adjacent_probe_context_terms = _compile_named_terms(
            INFRA_ADJACENT_PROBE_CONTEXT_TERMS,
            literal=True,
        )
        self._compiled_terms = {
            category: {
                "blocked_terms": _compile_named_terms(spec.get("blocked_terms", ())),
                "density_terms": _compile_named_terms(spec.get("density_terms", ())),
                "path_terms": _compile_named_terms(
                    spec.get("path_terms", ()),
                    path=True,
                ),
            }
            for category, spec in self.rules.items()
        }

    def _scan(self, payload: Any) -> tuple[tuple[str, ...], tuple[str, ...], int]:
        normalized = _normalize_payload(payload)
        punctuation_folded = _collapse_spaced_letters(
            _strip_punctuation_for_matching(normalized)
        )
        stitched = _stitch_known_split_terms(punctuation_folded)
        blocked_terms: list[str] = []
        trigger_categories: list[str] = []
        search_payloads = (
            normalized,
            punctuation_folded,
            _collapse_spaced_letters(punctuation_folded),
            stitched,
        )
        infra_adjacent_density_hit_count = 0

        for category, spec in self.rules.items():
            patterns = self._compiled_patterns.get(category, ())
            matched_blocked_terms = _matched_terms(
                self._compiled_terms.get(category, {}).get("blocked_terms", ()),
                search_payloads,
            )
            if any(
                pattern.search(candidate)
                for candidate in search_payloads
                for pattern in patterns
            ):
                if matched_blocked_terms:
                    _append_unique(trigger_categories, category)
                    blocked_terms.extend(matched_blocked_terms)

            if category != "infrastructure_probe":
                continue

            compiled_term_spec = self._compiled_terms.get(category, {})
            path_terms = compiled_term_spec.get("path_terms", ())
            matched_path_terms = _matched_terms(path_terms, search_payloads)
            if matched_path_terms:
                _append_unique(trigger_categories, "infrastructure_probe")
                blocked_terms.extend(matched_path_terms)

            density_terms = compiled_term_spec.get("density_terms", ())
            matched_density_terms = _matched_terms(density_terms, search_payloads)
            density_probe_context_terms = _matched_terms(
                self._compiled_density_probe_context_terms,
                search_payloads,
            )
            if len(matched_density_terms) >= 3 and density_probe_context_terms:
                _append_unique(trigger_categories, "infrastructure_probe")
                blocked_terms.extend(matched_density_terms)
                blocked_terms.extend(density_probe_context_terms)

                if len(matched_density_terms) > 3:
                    _append_unique(trigger_categories, "high_density_probe")

        infra_adjacent_hits = _matched_terms(
            self._compiled_infra_adjacent_terms,
            search_payloads,
        )
        infra_adjacent_probe_context_terms = _matched_terms(
            self._compiled_infra_adjacent_probe_context_terms,
            search_payloads,
        )
        if (
            len(infra_adjacent_hits) >= INFRA_ADJACENT_DENSITY_THRESHOLD
            and infra_adjacent_probe_context_terms
        ):
            _append_unique(trigger_categories, INFRA_ADJACENT_DENSITY_TRIGGER)
            blocked_terms.extend(infra_adjacent_hits)
            blocked_terms.extend(infra_adjacent_probe_context_terms)
            infra_adjacent_density_hit_count = len(infra_adjacent_hits)

        deduped_terms = tuple(dict.fromkeys(blocked_terms))
        deduped_categories = tuple(dict.fromkeys(trigger_categories))
        return deduped_terms, deduped_categories, infra_adjacent_density_hit_count

    def match(self, payload: Any) -> tuple[str, ...]:
        blocked_terms, _, _ = self._scan(payload)
        return blocked_terms

    def evaluate_preflight(self, payload: Any) -> dict[str, Any]:
        blocked_terms, trigger_categories, infra_adjacent_density_hit_count = self._scan(payload)
        if not blocked_terms:
            return {"status": "clean"}

        details = [f"trigger_category: {category}" for category in trigger_categories]
        extra_fields = (
            {INFRA_ADJACENT_DENSITY_HIT_COUNT_FIELD: infra_adjacent_density_hit_count}
            if INFRA_ADJACENT_DENSITY_TRIGGER in trigger_categories
            and infra_adjacent_density_hit_count >= INFRA_ADJACENT_DENSITY_THRESHOLD
            else None
        )
        return PolicyViolationError(
            blocked_terms=blocked_terms,
            details=details,
            extra_fields=extra_fields,
        ).to_payload()

    def check_or_raise(self, payload: Any) -> None:
        blocked_terms, trigger_categories, infra_adjacent_density_hit_count = self._scan(payload)
        if blocked_terms:
            details = [f"trigger_category: {category}" for category in trigger_categories]
            extra_fields = (
                {INFRA_ADJACENT_DENSITY_HIT_COUNT_FIELD: infra_adjacent_density_hit_count}
                if INFRA_ADJACENT_DENSITY_TRIGGER in trigger_categories
                and infra_adjacent_density_hit_count >= INFRA_ADJACENT_DENSITY_THRESHOLD
                else None
            )
            raise PolicyViolationError(
                blocked_terms=blocked_terms,
                details=details,
                extra_fields=extra_fields,
            )

    def rejection_payload(
        self,
        blocked_terms: Sequence[str],
        details: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        return PolicyViolationError(
            blocked_terms=blocked_terms,
            details=details,
        ).to_payload()
