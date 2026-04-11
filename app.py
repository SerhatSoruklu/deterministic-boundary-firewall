import json
import os
import random
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

REMOTE_MCP_SERVER_DIR = Path(__file__).resolve().parent / "remote-mcp-server"
if REMOTE_MCP_SERVER_DIR.exists():
    sys.path.insert(0, str(REMOTE_MCP_SERVER_DIR))

from policy_firewall import Level2StrictFirewall  # noqa: E402
from policy_firewall import PolicyViolationError  # noqa: E402
from policy_firewall import build_inspection_surface  # noqa: E402

DEFAULT_MODEL_POOL = [
    "gpt-5.4",
    "gpt-5-mini",
    "gpt-5-nano",
    "gpt-4.1-mini",
    "gpt-4.1-nano",
]
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
CHATPDM_VIRTUAL_RACK = "us-central-node-04"
CHATPDM_POLICY_ENCLAVE = "level-2-strict"
REQUEST_TIMEOUT_SECONDS = 60


class TransportRequestRejected(Exception):
    def __init__(self, payload: dict[str, Any]) -> None:
        super().__init__(payload.get("error", {}).get("message", "ERR_403_POLICY_VIOLATION"))
        self.payload = payload


class ChatPdmTransport:
    def __init__(self, api_key: str, firewall: Level2StrictFirewall | None = None) -> None:
        self.api_key = api_key
        self.firewall = firewall or Level2StrictFirewall()

    def _build_request_config(self, model: str, prompt: str) -> dict[str, Any]:
        return {
            "url": OPENAI_RESPONSES_URL,
            "method": "POST",
            "headers": {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "X-ChatPDM-Virtual-Rack": CHATPDM_VIRTUAL_RACK,
                "X-ChatPDM-Policy-Enclave": CHATPDM_POLICY_ENCLAVE,
            },
            "data": {
                "model": model,
                "input": prompt,
            },
            "params": {},
            "timeout": REQUEST_TIMEOUT_SECONDS,
        }

    def build_request_config(self, model: str, prompt: str) -> dict[str, Any]:
        # Public for compatibility. send() uses the private helper so the
        # request-config construction path stays explicit.
        return self._build_request_config(model, prompt)

    def _firewall_inspection_payload(self, config: dict[str, Any]) -> str:
        # Headers are transport metadata, not security inputs. The firewall only
        # inspects the request body and query-style params that carry prompt data.
        return json.dumps(
            build_inspection_surface(
                data=config.get("data"),
                params=config.get("params"),
            ),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def _request_interceptor(self, config: dict[str, Any]) -> dict[str, Any]:
        payload = self._firewall_inspection_payload(config)

        try:
            self.firewall.check_or_raise(payload)
        except PolicyViolationError as exc:
            raise TransportRequestRejected(exc.to_payload()) from exc

        return config

    def send(self, model: str, prompt: str) -> dict[str, Any]:
        config = self._request_interceptor(self._build_request_config(model, prompt))

        payload = json.dumps(config["data"]).encode("utf-8")
        req = request.Request(
            config["url"],
            data=payload,
            headers=config["headers"],
            method=config["method"],
        )

        with request.urlopen(req, timeout=config["timeout"]) as response:
            return json.loads(response.read().decode("utf-8"))


chatPdmClient = ChatPdmTransport(api_key="")


def load_dotenv(path: str = ".env") -> None:
    env_path = Path(path)
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


def get_model_pool() -> list[str]:
    raw = os.getenv("OPENAI_MODEL_POOL", "").strip()
    if not raw:
        return DEFAULT_MODEL_POOL

    pool = [item.strip() for item in raw.split(",") if item.strip()]
    return pool or DEFAULT_MODEL_POOL


def extract_output_text(response_data: dict) -> str:
    output_text = response_data.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    parts: list[str] = []
    for output_item in response_data.get("output", []):
        for content_item in output_item.get("content", []):
            text = content_item.get("text")
            if isinstance(text, str) and text:
                parts.append(text)

    if parts:
        return "".join(parts).strip()

    return json.dumps(response_data, indent=2, ensure_ascii=False)


def call_openai(model: str, prompt: str, api_key: str) -> dict:
    transport = ChatPdmTransport(api_key=api_key, firewall=chatPdmClient.firewall)
    return transport.send(model=model, prompt=prompt)


def main() -> int:
    load_dotenv()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print(
            "Missing OPENAI_API_KEY. Put it in your environment or a .env file.",
            file=sys.stderr,
        )
        return 1

    prompt = " ".join(sys.argv[1:]).strip() or "Write one friendly sentence introducing yourself."

    model = random.choice(get_model_pool())

    try:
        response_data = call_openai(model=model, prompt=prompt, api_key=api_key)
    except TransportRequestRejected as exc:
        print(json.dumps(exc.payload, indent=2, ensure_ascii=False))
        return 0
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        print(f"OpenAI API error ({exc.code}): {details}", file=sys.stderr)
        return 1
    except error.URLError as exc:
        print(f"Network error: {exc.reason}", file=sys.stderr)
        return 1

    print(f"Model: {model}")
    print(f"Prompt: {prompt}")
    print()
    print(extract_output_text(response_data))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
