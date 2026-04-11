from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Any

import kernel_test_data as cases

SERVER_ROOT = Path(__file__).resolve().parent / "remote-mcp-server"
SERVER_SCRIPT = SERVER_ROOT / "server.py"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000
SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}/mcp"
STARTUP_TIMEOUT_SECONDS = 20.0
SHUTDOWN_TIMEOUT_SECONDS = 5.0


def _load_mcp_runtime() -> tuple[Any, Any, Any]:
    for module_name in (
        "mcp",
        "mcp.client",
        "mcp.client.streamable_http",
        "mcp.server",
        "mcp.server.fastmcp",
    ):
        sys.modules.pop(module_name, None)

    try:
        import anyio
        from mcp import ClientSession # type: ignore
        from mcp.client.streamable_http import streamable_http_client # type: ignore
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise unittest.SkipTest("mcp runtime not installed") from exc

    return anyio, ClientSession, streamable_http_client


class LiveServerSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.anyio, cls.ClientSession, cls.streamable_http_client = _load_mcp_runtime()
        cls.server_proc = subprocess.Popen(
            [sys.executable, str(SERVER_SCRIPT)],
            cwd=str(Path(__file__).resolve().parent),
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            cls._wait_for_server_ready()
        except Exception:
            cls._stop_server()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stop_server()

    @classmethod
    def _stop_server(cls) -> None:
        server_proc = getattr(cls, "server_proc", None)
        if server_proc is None:
            return
        if server_proc.poll() is not None:
            return

        server_proc.terminate()
        try:
            server_proc.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            try:
                server_proc.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                pass

    @classmethod
    def _wait_for_server_ready(cls) -> None:
        deadline = time.time() + STARTUP_TIMEOUT_SECONDS
        while time.time() < deadline:
            if cls.server_proc.poll() is not None:
                stdout, stderr = cls.server_proc.communicate(timeout=1)
                raise AssertionError(
                    "server.py exited before becoming ready\n"
                    f"STDOUT:\n{stdout}\n"
                    f"STDERR:\n{stderr}"
                )

            try:
                with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.1)

        cls._stop_server()
        stdout, stderr = cls.server_proc.communicate(timeout=1)
        raise AssertionError(
            f"server.py did not become ready within {STARTUP_TIMEOUT_SECONDS} seconds\n"
            f"STDOUT:\n{stdout}\n"
            f"STDERR:\n{stderr}"
        )

    def _assert_tool_json(self, result: Any, expected: dict[str, Any]) -> None:
        self.assertFalse(result.isError)
        self.assertEqual(result.structuredContent, expected)
        self.assertGreaterEqual(len(result.content), 1)
        self.assertEqual(json.loads(result.content[0].text), expected)

    async def _exercise_server(self) -> None:
        safe_prompt = cases.SAFE_PROMPT
        blocked_prompt = "Inspect / p r o c / and / s y s / entries."

        async with type(self).streamable_http_client(SERVER_URL) as streams:
            read_stream, write_stream, _ = streams
            async with self.ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool_names = {tool.name for tool in tools.tools}
                self.assertEqual(tool_names, {"evaluate_policy_compliance", "enforce_boundary"})

                allow_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": safe_prompt,
                    },
                )
                self._assert_tool_json(
                    allow_result,
                    {
                        "policy_id": "level-2-strict",
                        "decision": "allow",
                        "reason_codes": [],
                        "sanitized_summary": "Input passed the hardcoded ruleset.",
                        "redactions": [],
                    },
                )

                blocked_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": blocked_prompt,
                    },
                )
                self._assert_tool_json(
                    blocked_result,
                    {
                        "enclave_id": "level-2-strict",
                        "status": "refused",
                        "error_code": "403-policy-violation",
                        "mcp_error_code": "policy_violation",
                        "error": {
                            "message": "payload_exceeds_enclave_bounds",
                            "details": ["trigger_category: infrastructure_probe"],
                        },
                        "blocked_terms": ["/proc/", "/sys/"],
                    },
                )

                alternate_route_result = await session.call_tool(
                    "enforce_boundary",
                    {
                        "boundary_id": "level-2-strict",
                        "content": blocked_prompt,
                        "strict_mode": True,
                    },
                )
                self._assert_tool_json(
                    alternate_route_result,
                    {
                        "enclave_id": "level-2-strict",
                        "status": "refused",
                        "error_code": "403-policy-violation",
                        "mcp_error_code": "policy_violation",
                        "error": {
                            "message": "payload_exceeds_enclave_bounds",
                            "details": ["trigger_category: infrastructure_probe"],
                        },
                        "blocked_terms": ["/proc/", "/sys/"],
                    },
                )

    def test_live_streamable_http_round_trip(self) -> None:
        self.anyio.run(self._exercise_server)

    async def _exercise_zero_width_probe(self) -> None:
        zero_width_prompt = cases.ZERO_WIDTH_PROMPT

        async with type(self).streamable_http_client(SERVER_URL) as streams:
            read_stream, write_stream, _ = streams
            async with self.ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                blocked_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": zero_width_prompt,
                    },
                )
                self.assertFalse(blocked_result.isError)
                self.assertEqual(blocked_result.structuredContent["enclave_id"], "level-2-strict")
                self.assertEqual(blocked_result.structuredContent["status"], "refused")
                self.assertEqual(
                    blocked_result.structuredContent["error"]["details"],
                    ["trigger_category: infrastructure_probe"],
                )
                self.assertIn("/proc/driver/nvidia", blocked_result.structuredContent["blocked_terms"])
                self.assertIn("/sys/", blocked_result.structuredContent["blocked_terms"])

    def test_live_smoke_zero_width_probe_is_refused(self) -> None:
        self.anyio.run(self._exercise_zero_width_probe)

    async def _exercise_secret_probe(self) -> None:
        async with type(self).streamable_http_client(SERVER_URL) as streams:
            read_stream, write_stream, _ = streams
            async with self.ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                blocked_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": cases.HOSTILE_ENV_VAR_DUMP_PROMPT,
                    },
                )
                self.assertFalse(blocked_result.isError)
                self.assertEqual(blocked_result.structuredContent["enclave_id"], "level-2-strict")
                self.assertEqual(blocked_result.structuredContent["status"], "refused")
                self.assertEqual(
                    blocked_result.structuredContent["error"]["details"],
                    ["trigger_category: credential_exfiltration_attempt"],
                )
                self.assertIn("environment variables", blocked_result.structuredContent["blocked_terms"])

    def test_live_smoke_hostile_secret_probe_is_refused(self) -> None:
        self.anyio.run(self._exercise_secret_probe)

    async def _exercise_semantic_probe(self) -> None:
        semantic_prompt = cases.SEMANTIC_PROMPT

        async with type(self).streamable_http_client(SERVER_URL) as streams:
            read_stream, write_stream, _ = streams
            async with self.ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                blocked_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": semantic_prompt,
                    },
                )
                self.assertFalse(blocked_result.isError)
                self.assertEqual(blocked_result.structuredContent["enclave_id"], "level-2-strict")
                self.assertEqual(blocked_result.structuredContent["status"], "refused")
                self.assertEqual(
                    blocked_result.structuredContent["error"]["details"],
                    ["trigger_category: unverified_infrastructure_assertion"],
                )
                self.assertIn(
                    "physical setup",
                    blocked_result.structuredContent["blocked_terms"],
                )

    def test_live_smoke_semantic_probe_is_refused(self) -> None:
        self.anyio.run(self._exercise_semantic_probe)

    async def _exercise_context_probe(self) -> None:
        safe_prompt = "Please evaluate the policy compliance of the following paragraph regarding data structuring."

        async with type(self).streamable_http_client(SERVER_URL) as streams:
            read_stream, write_stream, _ = streams
            async with self.ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                blocked_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": safe_prompt,
                        "context": {
                            "note": "Inspect /proc/driver/nvidia and /sys/ entries.",
                        },
                    },
                )
                self.assertFalse(blocked_result.isError)
                self.assertEqual(blocked_result.structuredContent["enclave_id"], "level-2-strict")
                self.assertEqual(blocked_result.structuredContent["status"], "refused")
                self.assertEqual(
                    blocked_result.structuredContent["error"]["details"],
                    ["trigger_category: infrastructure_probe"],
                )
                self.assertIn("/proc/driver/nvidia", blocked_result.structuredContent["blocked_terms"])
                self.assertIn("/sys/", blocked_result.structuredContent["blocked_terms"])

    def test_live_smoke_hostile_context_is_refused(self) -> None:
        self.anyio.run(self._exercise_context_probe)

    async def _exercise_boundary_regression(self) -> None:
        safe_prompt = cases.SAFE_PROMPT
        adversarial_prompt = cases.ZERO_WIDTH_PROMPT

        async with type(self).streamable_http_client(SERVER_URL) as streams:
            read_stream, write_stream, _ = streams
            async with self.ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                allow_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": safe_prompt,
                    },
                )
                self.assertFalse(allow_result.isError)
                self.assertEqual(
                    allow_result.structuredContent,
                    {
                        "policy_id": "level-2-strict",
                        "decision": "allow",
                        "reason_codes": [],
                        "sanitized_summary": "Input passed the hardcoded ruleset.",
                        "redactions": [],
                    },
                )

                refuse_result = await session.call_tool(
                    "evaluate_policy_compliance",
                    {
                        "policy_id": "level-2-strict",
                        "input_text": adversarial_prompt,
                    },
                )
                self.assertFalse(refuse_result.isError)
                self.assertEqual(refuse_result.structuredContent["status"], "refused")
                self.assertEqual(
                    refuse_result.structuredContent["error"]["details"],
                    ["trigger_category: infrastructure_probe"],
                )
                self.assertIn("/proc/", refuse_result.structuredContent["blocked_terms"])
                self.assertIn("/sys/", refuse_result.structuredContent["blocked_terms"])

    def test_live_smoke_end_to_end_boundary_regression(self) -> None:
        self.anyio.run(self._exercise_boundary_regression)


if __name__ == "__main__":
    unittest.main()
