"""Application boundaries: task isolation, confirmations, interruption and local HTTP."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app_server import Application, Core, Run, Server, endpoint, task_id

ID = "ctf-1234567890abcdef"


class FixtureCore:
    def __init__(self, root):
        self.root = Path(root)
        self.calls = []

    def tools(self):
        return [{"name": n, "description": n, "inputSchema": {"type": "object"}}
            for n in ("ctf_progress", "ctf_analyze", "ctf_call", "ctf_note", "ctf_tools", "ctf_start", "ctf_finish")]

    def call(self, name, args=None):
        self.calls.append((name, copy.deepcopy(args or {})))
        if name == "ctf_progress":
            return {"ok": True, "task": {"task_id": ID, "title": "test", "description": "自建测试", "events": []},
                "workflow": {"phase": "analysis"}, "recent_evidence": []}
        return {"ok": True, "result": 12, "workflow": {"phase": "analysis"}}


def call(name="ctf_analyze", args=None, identifier="model-call-1"):
    return {"id": identifier, "type": "function", "function": {"name": name, "arguments": json.dumps(
        args or {"task_id": ID, "tool": "math_gcd", "arguments": {"values": [48, 60]}}, ensure_ascii=False)}}


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core = FixtureCore(self.temp.name)
        self.app = Application(self.core, Path(self.temp.name)/"app")
        self.run = Run(ID, {"model": "fixture"}, 3)
        self.app.runs[ID] = self.run

    def tearDown(self):
        self.run.stop.set()
        self.run.answer.set()
        self.temp.cleanup()

    def test_calls_preserve_task_and_execution_request_id(self):
        response = self.app._execute(self.run, call())
        self.assertTrue(response["ok"])
        _, args = self.core.calls[-1]
        self.assertEqual(args["task_id"], ID)
        self.assertIn(self.run.run_id, args["request_id"])

    def test_other_task_and_native_tools_are_never_executed(self):
        for request in (call(args={"task_id": "ctf-0000000000000000", "tool": "math_gcd"}), call("shell")):
            self.assertFalse(self.app._execute(self.run, request)["ok"])
        self.assertFalse(self.core.calls)

    def test_different_run_can_reuse_provider_id_without_replaying_old_action(self):
        self.app._execute(self.run, call())
        first = self.core.calls[-1][1]["request_id"]
        self.app._execute(Run(ID, {"model": "other"}, 3), call())
        self.assertNotEqual(first, self.core.calls[-1][1]["request_id"])

    def test_confirmation_rejection_does_not_execute(self):
        result = []
        request = call("ctf_call", {"task_id": ID, "tool": "kali_run", "arguments": {"confirm": True, "argv": ["pwd"]}})
        worker = threading.Thread(target=lambda: result.append(self.app._execute(self.run, request)))
        worker.start()
        for _ in range(100):
            if self.run.pending:
                break
            time.sleep(.01)
        self.assertEqual(self.run.status, "waiting_confirmation")
        self.assertFalse(self.core.calls)
        self.app.confirm({"task_id": ID, "id": self.run.pending["id"], "allow": False})
        worker.join(2)
        self.assertFalse(result[0]["ok"])
        self.assertFalse(self.core.calls)

    def test_confirmation_approval_executes_only_requested_call(self):
        result = []
        request = call("ctf_call", {"task_id": ID, "tool": "kali_run", "arguments": {"confirm": True}})
        worker = threading.Thread(target=lambda: result.append(self.app._execute(self.run, request)))
        worker.start()
        for _ in range(100):
            if self.run.pending:
                break
            time.sleep(.01)
        self.app.confirm({"task_id": ID, "id": self.run.pending["id"], "allow": True})
        worker.join(2)
        self.assertTrue(result[0]["ok"])
        self.assertEqual(len(self.core.calls), 1)
        self.assertTrue(self.core.calls[0][1]["arguments"]["confirm"])

    def test_key_is_not_written_to_metadata_or_events(self):
        self.run.status = "idle"
        self.app.set_settings({"base_url": "https://example.invalid/v1", "model": "fixture", "api_key": "secret-for-test"})
        self.app.event(self.run, "error", "echo secret-for-test")
        self.assertNotIn("secret-for-test", (self.app.home/"model.json").read_text())
        self.assertNotIn("secret-for-test", (self.app.home/"runs"/(ID+".jsonl")).read_text())

    def test_switch_model_while_running_is_rejected(self):
        with self.assertRaises(ValueError):
            self.app.set_settings({"base_url": "https://example.invalid/v1", "model": "new"})

    def test_model_loop_uses_existing_progress_and_only_system_tools(self):
        calls = []
        def model(config, key, messages, tools):
            calls.append(copy.deepcopy(messages))
            self.assertNotIn("ctf_start", {t["function"]["name"] for t in tools})
            return {"role": "assistant", "content": None, "tool_calls": [call()]} if len(calls) == 1 else {"role": "assistant", "content": "自建计算完成，未验证比赛答案。"}
        self.app.provider = model
        self.app._run(self.run, {"model": "fixture"}, "", "继续自建测试")
        self.assertEqual(self.run.status, "idle")
        self.assertEqual(self.core.calls[0][0], "ctf_progress")
        self.assertEqual(calls[-1][-1]["role"], "tool")
        self.assertTrue(json.loads(calls[-1][-1]["content"])["ok"])

    def test_restart_reads_history_but_does_not_replay_requests(self):
        self.app.event(self.run, "model_calls", "pending", calls=[call()])
        reloaded = Application(self.core, self.app.home)
        self.assertEqual(reloaded.run_state(ID)["status"], "idle")
        self.assertEqual(len(reloaded.run_state(ID)["events"]), 1)
        self.assertFalse(self.core.calls)

    def test_api_endpoint_rejects_remote_plaintext_and_credential_url(self):
        for value in ("http://example.com/v1", "https://key:password@example.com/v1", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                endpoint(value)
        self.assertEqual(endpoint("http://127.0.0.1:11434/v1/"), "http://127.0.0.1:11434/v1/chat/completions")

    def test_upload_rejects_path_escape(self):
        with self.assertRaises(ValueError):
            self.app.upload({"name": "../task.json", "data": ""})
        with self.assertRaises(ValueError):
            task_id("../ctf-1234567890abcdef")


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = Application(FixtureCore(self.temp.name), Path(self.temp.name)/"home")
        self.server = Server(("127.0.0.1", 0), self.app)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.url = "http://127.0.0.1:%s" % self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.worker.join(3)
        self.server.server_close()
        self.temp.cleanup()

    def request(self, path, method="GET", headers=None, body=None):
        return urllib.request.urlopen(urllib.request.Request(self.url+path, method=method, headers=headers or {}, data=body), timeout=3)

    def test_anonymous_and_foreign_origin_cannot_read_tasks(self):
        for headers in ({}, {"Cookie": "ctf_app="+self.server.secret, "Origin": "https://unrelated.invalid"}):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request("/api/tasks", headers=headers)
            self.assertEqual(error.exception.code, 403)

    def test_authenticated_client_reads_same_core_and_static_ui(self):
        cookie = {"Cookie": "ctf_app="+self.server.secret}
        with self.request("/api/task?id="+ID, headers=cookie) as result:
            self.assertEqual(json.load(result)["task"]["task_id"], ID)
        with self.request("/", headers=cookie) as result:
            self.assertIn("解题工作台", result.read().decode())

    def test_handoff_identifies_existing_task_and_core(self):
        with self.request("/api/handoff?id="+ID, headers={"Cookie": "ctf_app="+self.server.secret}) as result:
            text = json.load(result)["text"]
            self.assertIn(ID, text)
            self.assertIn(str(self.app.core.root), text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
