"""Jev transport, closed-set validation, protocol and evidence integration; no paid calls."""
import io
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import ctf_jev as jev
import ctf_os as service
import ctf_wp as wp

QUESTIONS = {
    "path": {"type": "choice", "instructions": "Choose the supported approach",
             "criteria": {"a": "Known approach", "none": "Insufficient evidence"}},
    "supported": {"type": "noul", "instructions": "Is the observation supported?"},
    "progress": {"type": "score", "instructions": "Rate current progress",
                 "criteria": ["No supporting evidence", "Supported by observed output"]},
}


def response():
    return {"model": "typesafe/jev-1.13-test", "id": "test-request", "provider": "fixture",
            "answers": {
                "path": {"type": "choice", "choice": "a", "probabilities": {"a": .9, "none": .1}, "confidence": .8},
                "supported": {"type": "noul", "noul": .9},
                "progress": {"type": "score", "score": .9, "probabilities": {"0": .1, "1": .9},
                             "confidence": .8, "legend": {"0": "No supporting evidence", "1": "Supported by observed output"}}},
            "usage": {"cost": 0, "input_tokens": 10}}


def wire(body=None):
    return io.BytesIO(json.dumps(response() if body is None else body).encode())


class JevTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"CTF_JEV_CONFIG": str(Path(self.directory.name) / "jev.json"),
            "CTF_JEV_ENDPOINT": jev.ENDPOINT, "CTF_JEV_MODEL": jev.MODEL,
            "OPENROUTER_API_KEY": "fixture-secret-never-log"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.directory.cleanup()

    def ask(self):
        return jev.decide({"state": {"observation": "self-created fixture"}, "questions": QUESTIONS, "confirm": True})

    def test_status_does_not_make_network_or_claim_live_verification(self):
        with patch.object(jev, "_open") as transport:
            result = jev.status()
        transport.assert_not_called()
        self.assertTrue(result["configured"])
        self.assertFalse(result["live_verified"])
        self.assertNotIn("fixture-secret", json.dumps(result))

    def test_missing_key_fails_without_network(self):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}), patch.object(jev, "_open") as transport:
            result = self.ask()
        transport.assert_not_called()
        self.assertEqual(result["error_code"], "jev_not_configured")

    def test_real_decisions_request_shape_and_three_answer_types(self):
        with patch.object(jev, "_open", return_value=wire()) as transport:
            result = self.ask()
        request = transport.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, jev.ENDPOINT)
        self.assertEqual(payload["model"], jev.MODEL)
        self.assertEqual(payload["questions"], QUESTIONS)
        self.assertNotIn("messages", payload)
        self.assertEqual(request.get_header("Authorization"), "Bearer fixture-secret-never-log")
        self.assertEqual(result["answers"]["progress"]["score"], .9)
        self.assertFalse(result["solved_verified"])

    def test_loopback_transport_sends_request_and_parses_response(self):
        captured = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                captured["path"] = self.path
                captured["authorization"] = self.headers.get("Authorization")
                captured["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                data = json.dumps(response()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()
            with patch.dict(os.environ, {"CTF_JEV_ENDPOINT":
                "http://127.0.0.1:%s/api/alpha/decisions" % server.server_port}):
                result = self.ask()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(captured["path"], "/api/alpha/decisions")
        self.assertEqual(captured["body"]["questions"], QUESTIONS)
        self.assertEqual(captured["authorization"], "Bearer fixture-secret-never-log")
        self.assertEqual(result["request_id"], "test-request")

    def test_confirmation_cannot_be_string(self):
        with patch.object(jev, "_open") as transport:
            result = service.call_tool("jev_decide", {"confirm": "true", "state": "fixture", "questions": QUESTIONS})
        transport.assert_not_called()
        self.assertEqual(result["error_code"], "confirmation_required")

    def test_invalid_questions_rejected_before_network(self):
        for questions in ({}, {"q": {"type": "choice", "instructions": "x", "criteria": ["a", "b"]}},
                          {"q": {"type": "score", "instructions": "x", "criteria": ["one"]}}):
            with patch.object(jev, "_open") as transport:
                result = jev.decide({"state": "fixture", "questions": questions, "confirm": True})
            transport.assert_not_called()
            self.assertEqual(result["error_code"], "invalid_arguments")

    def test_payload_limit_rejected_before_network(self):
        with patch.object(jev, "_open") as transport:
            result = jev.decide({"state": "x" * jev.MAX_BYTES, "questions": QUESTIONS, "confirm": True})
        transport.assert_not_called()
        self.assertEqual(result["error_code"], "invalid_arguments")

    def test_malformed_answers_never_become_success(self):
        bodies = [response() for _ in range(6)]
        bodies[0]["answers"].pop("supported")
        bodies[1]["answers"]["path"]["choice"] = "fabricated-action"
        bodies[2]["answers"]["supported"]["noul"] = True
        bodies[3]["answers"]["path"]["probabilities"]["a"] = float("nan")
        bodies[4]["answers"]["progress"]["legend"]["0"] = "different rubric"
        bodies[5]["answers"]["path"]["choice"] = ["a"]
        for body in bodies:
            with patch.object(jev, "_open", return_value=wire(body)):
                result = self.ask()
            self.assertEqual(result["error_code"], "invalid_response")

    def test_http_error_does_not_leak_provider_body_or_retry_auth(self):
        error = urllib.error.HTTPError(jev.ENDPOINT, 401, "echo fixture-secret-never-log", {},
                                      io.BytesIO(b"fixture-secret-never-log"))
        with patch.object(jev, "_open", side_effect=error) as transport:
            result = self.ask()
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(result["http_status"], 401)
        self.assertNotIn("fixture-secret", json.dumps(result))

    def test_rate_limit_retries_are_bounded(self):
        errors = [urllib.error.HTTPError(jev.ENDPOINT, 429, "busy", {}, io.BytesIO()) for _ in range(3)]
        with patch.object(jev, "_open", side_effect=errors) as transport, patch.object(jev.time, "sleep"):
            result = self.ask()
        self.assertEqual(transport.call_count, 3)
        self.assertEqual(result["error_code"], "jev_http_error")

    def test_timeout_not_retried_and_existing_tools_still_work(self):
        with patch.object(jev, "_open", side_effect=TimeoutError) as transport:
            result = self.ask()
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(result["error_code"], "jev_timeout")
        self.assertEqual(service.call_tool("math_gcd", {"values": [48, 60]})["result"]["result"], 12)

    def test_redirect_does_not_forward_credential(self):
        self.assertIsNone(jev.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid"))

    def test_provider_echo_of_key_is_redacted(self):
        body = response()
        body["provider"] = "fixture-secret-never-log"
        with patch.object(jev, "_open", return_value=wire(body)):
            result = self.ask()
        self.assertEqual(result["provider"], "[REDACTED]")

    def test_triage_uses_current_observations_only(self):
        with patch.object(jev, "decide", return_value={"fixture": True}) as decide:
            jev.triage({"challenge": "self-created binary", "observations": "ELF", "confirm": True})
        args = decide.call_args.args[0]
        self.assertEqual(args["state"]["observations"], "ELF")
        self.assertIn("unknown", args["questions"]["category"]["criteria"])
        self.assertEqual(set(args["questions"]), {"category", "needs_more_evidence"})

    def test_optional_configuration_failure_does_not_break_import(self):
        Path(os.environ["CTF_JEV_CONFIG"]).write_text('{"api_key":"do-not-store"}')
        self.assertFalse(jev.status()["configured"])
        self.assertEqual(service.call_tool("math_gcd", {"values": [48, 60]})["result"]["result"], 12)

    def test_mcp_call_records_decision_and_failure_in_isolated_wp(self):
        with patch.object(wp, "ROOT", Path(self.directory.name) / "evidence"):
            wp.init({"case": "jev_fixture"})
            arguments = {"state": "fixture", "questions": QUESTIONS, "confirm": True, "wp_case": "jev_fixture"}
            with patch.object(jev, "_open", return_value=wire()):
                rpc = service.mcp_handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "jev_decide", "arguments": arguments}})
            self.assertFalse(rpc["result"]["isError"])
            with patch.object(jev, "_open", side_effect=TimeoutError):
                failed = service.call_tool("jev_decide", arguments)
            self.assertFalse(failed["ok"])
            self.assertEqual(wp.status({"case": "jev_fixture"})["calls"], 2)
            report = wp.build({"case": "jev_fixture"})
            text = Path(report["path"]).read_text(encoding="utf-8")
            self.assertIn("jev_decide", text)
            self.assertIn("jev_timeout", text)
            self.assertFalse(report["solved_verified"])

    def test_stdio_handshake_lists_jev_tools_without_network(self):
        messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "jev_status", "arguments": {}}}]
        process = subprocess.run([sys.executable, str(service.__file__), "--stdio"],
            input="".join(json.dumps(x) + "\n" for x in messages), text=True,
            capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual([row["id"] for row in rows], [1, 2, 3])
        names = {item["name"] for item in rows[1]["result"]["tools"]}
        self.assertTrue({"jev_status", "jev_decide", "jev_triage"}.issubset(names))


if __name__ == "__main__":
    unittest.main()
