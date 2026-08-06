import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


INSTALLER = Path(__file__).resolve().parents[1] / "integrations/agent-guard/install.sh"


class _GuardHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def _json(self, status, payload):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append({"path": self.path, "body": body})
        if self.path == "/v1/actions/evaluate":
            action = body.get("action") or {}
            target = action.get("target") or (action.get("parameters") or {}).get("path")
            if body.get("approval_id") == self.server.approval_id:
                self._json(
                    200,
                    {
                        "decision": "allow",
                        "action_hash": "sha256:approval",
                        "approval_id": self.server.approval_id,
                        "approval_resume": True,
                        "proof_id": "proof://approved",
                    },
                )
            elif target == "/etc/shadow" or (
                action.get("tool") == "shell"
                and "sqlite3" in (action.get("parameters") or {}).get("command", "")
                and "drop table" in (action.get("parameters") or {}).get("command", "").lower()
            ):
                action_id = (body.get("context") or {}).get("action_id")
                self._json(
                    200,
                    {
                        "decision": "require_approval",
                        "action_hash": "sha256:approval",
                        "approval_id": self.server.approval_id,
                        "approval": {
                            "approval_id": self.server.approval_id,
                            "action_id": action_id,
                            "action_hash": "sha256:approval",
                        },
                        "reason_codes": ["PROTECTED_FILESYSTEM_TARGET"],
                    },
                )
            else:
                self._json(200, {"decision": "allow", "action_hash": "sha256:allow", "proof_id": "proof://allow"})
            return
        if self.path.startswith("/v1/actions/") and self.path.endswith("/outcome"):
            self._json(202, {"status": "recorded"})
            return
        self._json(404, {"error": "not_found"})


class ClaudeInstallerTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _GuardHandler)
        self.server.requests = []
        self.server.approval_id = "approval-test"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "KENNING_API_URL": f"http://127.0.0.1:{self.server.server_port}",
                "KENNING_PAT": "kta_pat_test_only",
                "KENNING_TENANT_ID": "tenant-test",
                "KENNING_ENVIRONMENT": "development",
                "KENNING_AGENT_ID": "claude-test-agent",
                "KENNING_INVOKED_BY": "claude-test",
            }
        )

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def run_installer(self, project, *arguments, environment=None):
        return subprocess.run(
            ["bash", str(INSTALLER), "--client", "claude-code", "--project-dir", str(project), *arguments],
            cwd=INSTALLER.parents[2],
            env=environment or self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def run_hook(self, hook, payload):
        return subprocess.run(
            ["python3", str(hook)],
            input=json.dumps(payload),
            cwd=hook.parents[2],
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def test_claude_install_enforces_filesystem_approval_and_uninstalls_cleanly(self):
        with tempfile.TemporaryDirectory(prefix="kenning claude installer ") as directory:
            project = Path(directory)
            (project / ".claude").mkdir()
            (project / ".claude/settings.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo unrelated"}]}
                            ]
                        },
                        "mcpServers": {"unrelated": {"type": "url", "url": "https://example.test/mcp"}},
                    }
                ),
                encoding="utf-8",
            )

            installed = self.run_installer(project)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            settings_path = project / ".claude/settings.json"
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            settings_text = json.dumps(settings)
            self.assertNotIn("kta_pat_test_only", settings_text)
            self.assertEqual(
                settings["mcpServers"]["kenning-agent-guard"]["headers"]["Authorization"],
                "Bearer ${KENNING_PAT}",
            )
            self.assertEqual(
                settings["mcpServers"]["kenning-agent-guard"]["headers"]["X-Kenning-Tenant-Id"],
                "${KENNING_TENANT_ID}",
            )
            self.assertIn("echo unrelated", settings_text)
            self.assertIn("https://example.test/mcp", settings_text)
            self.assertTrue((project / ".claude/kenning-guard-hook.py").exists())
            self.assertEqual((project / ".claude/kenning-guard-hook.py").stat().st_mode & 0o777, 0o700)
            self.assertIn("PostToolUse", settings["hooks"])
            self.assertIn("PostToolUseFailure", settings["hooks"])
            for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
                self.assertIn(
                    "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|Glob",
                    [group["matcher"] for group in settings["hooks"][event]],
                )

            hook = project / ".claude/kenning-guard-hook.py"
            blocked_input = {
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_use_id": "blocked-call",
                "cwd": str(project),
                "tool_input": {"file_path": "/etc/shadow", "content": "not written"},
            }
            blocked = self.run_hook(hook, blocked_input)
            self.assertEqual(blocked.returncode, 2, blocked.stderr)
            self.assertIn("approval-test", blocked.stderr)

            multi_edit = self.run_hook(
                hook,
                {
                    **blocked_input,
                    "tool_name": "MultiEdit",
                    "tool_use_id": "multi-edit-blocked-call",
                },
            )
            self.assertEqual(multi_edit.returncode, 2, multi_edit.stderr)
            self.assertIn("approval-test", multi_edit.stderr)

            retry = self.run_hook(
                hook,
                {**blocked_input, "tool_use_id": "approved-call"},
            )
            self.assertEqual(retry.returncode, 0, retry.stderr)
            outcome = self.run_hook(
                hook,
                {
                    **blocked_input,
                    "hook_event_name": "PostToolUseFailure",
                    "tool_use_id": "approved-call",
                },
            )
            self.assertEqual(outcome.returncode, 0, outcome.stderr)

            evaluations = [
                item
                for item in self.server.requests
                if item["path"] == "/v1/actions/evaluate"
                and item["body"].get("action", {}).get("tool") == "filesystem"
            ]
            self.assertEqual(evaluations[0]["body"]["action"]["operation"], "write")
            self.assertEqual(evaluations[0]["body"]["action"]["target"], "/etc/shadow")
            parameters = evaluations[0]["body"]["action"]["parameters"]
            self.assertNotIn("content", parameters)
            self.assertEqual(parameters["content_length"], len("not written"))
            self.assertRegex(parameters["content_sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn("not written", json.dumps(evaluations[0]["body"]))
            multi_edit_evaluations = [
                item
                for item in evaluations
                if item["body"]["action"]["operation"] == "modify"
            ]
            self.assertEqual(multi_edit_evaluations[0]["body"]["action"]["target"], "/etc/shadow")
            outcomes = [item for item in self.server.requests if item["path"].endswith("/outcome")]
            self.assertEqual(outcomes[-1]["body"]["status"], "failure")

            sqlite_blocked = self.run_hook(
                hook,
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_use_id": "sqlite-blocked-call",
                    "cwd": str(project),
                    "tool_input": {"command": 'sqlite3 green.sqlite3 "DROP TABLE green;"'},
                },
            )
            self.assertEqual(sqlite_blocked.returncode, 2, sqlite_blocked.stderr)
            self.assertIn("approval-test", sqlite_blocked.stderr)

            clean_environment = {key: value for key, value in os.environ.items() if not key.startswith("KENNING_")}
            uninstalled = self.run_installer(project, "--uninstall", environment=clean_environment)
            self.assertEqual(uninstalled.returncode, 0, uninstalled.stderr)
            final_text = settings_path.read_text(encoding="utf-8")
            self.assertNotIn("kenning-agent-guard", final_text)
            self.assertNotIn("kenning-guard-hook.py", final_text)
            self.assertIn("echo unrelated", final_text)
            self.assertIn("https://example.test/mcp", final_text)
            self.assertFalse(hook.exists())


if __name__ == "__main__":
    unittest.main()
