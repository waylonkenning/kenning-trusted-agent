import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import tomllib
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "integrations/agent-guard/install.sh"
HOOK_SOURCE = ROOT / "integrations/agent-guard/codex-guard-hook.py"
BRIDGE_SOURCE = ROOT / "integrations/agent-guard/codex-mcp-stdio.py"


class _CodexGuardHandler(BaseHTTPRequestHandler):
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
        self._json(200, self.server.health_payload if self.path == "/health" else {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        if self.path == "/mcp":
            if self.headers.get("Authorization") != "Bearer kta_pat_test_only":
                self._json(401, {"error": "unauthorized"})
                return
            if self.headers.get("X-Kenning-Tenant-Id") != "tenant-test":
                self._json(403, {"error": "wrong_tenant"})
                return
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "kenning-agent-guard", "version": "test"},
                    },
                },
            )
            return
        if self.path == "/v1/actions/evaluate":
            if self.server.expected_pat and self.headers.get("Authorization") != f"Bearer {self.server.expected_pat}":
                self._json(401, {"error": "unauthorized"})
                return
            if self.server.evaluate_status:
                status, payload = self.server.evaluate_status
                self._json(status, payload)
                return
            command = ((body.get("action") or {}).get("parameters") or {}).get("command", "")
            if body.get("approval_id") == self.server.approval_id:
                if self.server.approval_retry_response:
                    status, payload = self.server.approval_retry_response
                    self._json(status, payload)
                    return
                self._json(
                    200,
                    {
                        "decision": "allow",
                        "action_hash": self.server.approved_hash,
                        "approval_id": self.server.approval_id,
                        "proof_id": "proof://codex-approved",
                    },
                )
            elif "rmdir" in command or ("sqlite3" in command and "drop table" in command.lower()):
                action_id = (body.get("context") or {}).get("action_id")
                self._json(
                    200,
                    {
                        "decision": "require_approval",
                        "action_hash": self.server.approved_hash,
                        "approval_id": self.server.approval_id,
                        "approval": {
                            "approval_id": self.server.approval_id,
                            "action_id": action_id,
                            "action_hash": self.server.approved_hash,
                        },
                        "reason_codes": ["DESTRUCTIVE_FILESYSTEM_OPERATION"],
                    },
                )
            else:
                self._json(200, {"decision": "allow", "action_hash": "sha256:allow"})
            return
        if self.path.startswith("/v1/actions/") and self.path.endswith("/outcome"):
            self._json(202, {"status": "recorded"})
            return
        self._json(404, {"error": "not_found"})


class CodexInstallerTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _CodexGuardHandler)
        self.server.requests = []
        self.server.approval_id = "approval-codex-test"
        self.server.approved_hash = "sha256:codex-approved"
        self.server.approval_retry_response = None
        self.server.evaluate_status = None
        self.server.expected_pat = None
        self.server.health_payload = {
            "status": "ok",
            "service": "kenning-agent-guard",
            "environment": "development",
            "release_id": "test-release",
            "source_commit": "a" * 40,
        }
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "KENNING_API_URL": f"http://127.0.0.1:{self.server.server_port}",
                "KENNING_PAT": "kta_pat_test_only",
                "KENNING_TENANT_ID": "tenant-test",
                "KENNING_ENVIRONMENT": "development",
                "KENNING_AGENT_ID": "codex-test-agent",
                "KENNING_INVOKED_BY": "codex-test",
            }
        )

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def run_installer(self, project, *arguments, environment=None):
        return subprocess.run(
            ["bash", str(INSTALLER), "--client", "codex-cli", "--project-dir", str(project), *arguments],
            cwd=ROOT,
            env=environment or self.environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def run_hook(self, hook, payload, environment=None):
        return subprocess.run(
            ["python3", str(hook)],
            input=json.dumps(payload),
            cwd=ROOT,
            env=environment or self.environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )

    def create_pending_approval(self, directory):
        project = Path(directory)
        hook = project / "kenning-guard-hook.py"
        hook.write_text(HOOK_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
        hook.chmod(0o700)
        target = project / "denial-target"
        target.mkdir()
        blocked_input = {
            "hook_event_name": "PreToolUse",
            "tool_name": "exec_command",
            "tool_use_id": "denial-blocked-call",
            "cwd": str(project),
            "tool_input": {"cmd": f"rmdir {target}", "workdir": str(project)},
        }
        blocked = self.run_hook(hook, blocked_input)
        self.assertEqual(blocked.returncode, 0, blocked.stderr)
        self.assertEqual(json.loads(blocked.stdout)["decision"], "block")
        self.assertTrue(target.exists())
        return hook, target, blocked_input

    def test_denied_approval_is_not_reported_as_guard_unavailable(self):
        with tempfile.TemporaryDirectory(prefix="kenning codex denial ") as directory:
            hook, target, blocked_input = self.create_pending_approval(directory)
            self.server.approval_retry_response = (
                409,
                {
                    "error": "approval_not_approved",
                    "approval_id": self.server.approval_id,
                    "status": "denied",
                },
            )

            retry = self.run_hook(hook, {**blocked_input, "tool_use_id": "denial-retry-call"})

            self.assertEqual(retry.returncode, 0, retry.stderr)
            result = json.loads(retry.stdout)
            self.assertEqual(result["decision"], "block")
            self.assertIn("approval denied", result["reason"])
            self.assertNotIn("unavailable", result["reason"].lower())
            self.assertTrue(target.exists(), "the denied destructive command ran")

    def test_expired_approval_is_reported_as_decided(self):
        with tempfile.TemporaryDirectory(prefix="kenning codex expired ") as directory:
            hook, target, blocked_input = self.create_pending_approval(directory)
            self.server.approval_retry_response = (
                409,
                {
                    "error": "approval_expired_or_already_decided",
                    "approval_id": self.server.approval_id,
                },
            )

            retry = self.run_hook(hook, {**blocked_input, "tool_use_id": "expired-retry-call"})

            self.assertEqual(retry.returncode, 0, retry.stderr)
            result = json.loads(retry.stdout)
            self.assertEqual(result["decision"], "block")
            self.assertIn("approval expired or already decided", result["reason"])
            self.assertTrue(target.exists(), "the expired approval allowed the destructive command")



    def test_cli_environment_overrides_stale_credentials_file(self):
        with tempfile.TemporaryDirectory(prefix="kenning codex stale credentials ") as directory:
            hook = Path(directory) / "kenning-guard-hook.py"
            hook.write_text(HOOK_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
            hook.chmod(0o700)
            (Path(directory) / "kenning-guard-credentials.json").write_text(
                json.dumps(
                    {
                        "api_url": self.environment["KENNING_API_URL"],
                        "pat": "stale-pat",
                        "tenant_id": "stale-tenant",
                        "environment": "production",
                    }
                ),
                encoding="utf-8",
            )
            self.server.expected_pat = "kta_pat_test_only"

            result = self.run_hook(
                hook,
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "tool_use_id": "stale-credentials-call",
                    "cwd": directory,
                    "tool_input": {"path": str(Path(directory) / "read-only-target")},
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            evaluations = [item for item in self.server.requests if item["path"] == "/v1/actions/evaluate"]
            self.assertEqual(evaluations[-1]["headers"]["Authorization"], "Bearer kta_pat_test_only")

    def test_auth_failure_identifies_environment_credentials(self):
        with tempfile.TemporaryDirectory(prefix="kenning codex auth failure ") as directory:
            hook = Path(directory) / "kenning-guard-hook.py"
            hook.write_text(HOOK_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
            hook.chmod(0o700)
            self.server.evaluate_status = (401, {"error": "unauthorized"})

            result = self.run_hook(
                hook,
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "tool_use_id": "auth-failure-call",
                    "cwd": directory,
                    "tool_input": {"path": str(Path(directory) / "read-only-target")},
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertIn("authentication failed", decision["reason"])
            self.assertIn("refresh KENNING_PAT", decision["reason"])
            self.assertNotIn("unavailable", decision["reason"].lower())

    def test_installer_rejects_cross_environment_endpoint(self):
        self.server.health_payload = {
            "status": "ok",
            "service": "kenning-agent-guard",
            "environment": "production",
            "release_id": "production-release",
            "source_commit": "b" * 40,
        }
        with tempfile.TemporaryDirectory(prefix="kenning codex wrong environment ") as directory:
            result = self.run_installer(Path(directory))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("endpoint environment is production; expected development", result.stderr)
            self.assertFalse((Path(directory) / ".codex" / "kenning-guard-credentials.json").exists())

    def test_installer_rejects_unverified_evaluation_results(self):
        for status, payload, message in (
            (200, {"decision": "unknown"}, "no valid decision"),
            (503, {"error": "service_unavailable"}, "Guard evaluation check failed"),
        ):
            with self.subTest(status=status):
                self.server.evaluate_status = (status, payload)
                with tempfile.TemporaryDirectory(prefix="kenning codex unverified evaluation ") as directory:
                    result = self.run_installer(Path(directory))

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn("Kenning Agent Guard installed", result.stdout)

    def test_guard_server_failure_remains_unavailable(self):
        with tempfile.TemporaryDirectory(prefix="kenning codex unavailable ") as directory:
            hook, target, blocked_input = self.create_pending_approval(directory)
            self.server.approval_retry_response = (503, {"error": "service_unavailable"})

            retry = self.run_hook(hook, {**blocked_input, "tool_use_id": "unavailable-retry-call"})

            self.assertEqual(retry.returncode, 0, retry.stderr)
            result = json.loads(retry.stdout)
            self.assertEqual(result["decision"], "block")
            self.assertIn("Guard service returned HTTP 503", result["reason"])
            self.assertTrue(target.exists(), "the unavailable Guard allowed the destructive command")

    def test_installer_enforces_destructive_codex_command_and_uninstalls_cleanly(self):
        with tempfile.TemporaryDirectory(prefix="kenning codex installer ") as directory:
            project = Path(directory)
            codex_dir = project / ".codex"
            codex_dir.mkdir()
            (codex_dir / "config.toml").write_text(
                'model = "test-model"\n\n[mcp_servers.unrelated]\nurl = "https://example.test/mcp"\n',
                encoding="utf-8",
            )
            (codex_dir / "hooks.json").write_text(
                json.dumps(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo unrelated"}]}
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            (codex_dir / "config.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "kenning-agent-guard": {"url": "https://old.example/mcp"},
                            "unrelated": {"url": "https://example.test/mcp"},
                        },
                        "instructions": ["./AGENTS.kenning.md", "./AGENTS.md"],
                    }
                ),
                encoding="utf-8",
            )

            installed = self.run_installer(project)
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            self.assertNotIn("kta_pat_test_only", installed.stdout + installed.stderr)

            config_path = codex_dir / "config.toml"
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(config["project_doc_fallback_filenames"], ["AGENTS.kenning.md"])
            self.assertEqual(
                config["mcp_servers"]["kenning-agent-guard"]["command"],
                "python3",
            )
            self.assertEqual(
                config["mcp_servers"]["kenning-agent-guard"]["args"],
                [str(codex_dir / "kenning-agent-guard-mcp.py")],
            )
            self.assertEqual(
                config["mcp_servers"]["kenning-agent-guard"]["cwd"],
                str(project),
            )
            self.assertEqual(config["mcp_servers"]["unrelated"]["url"], "https://example.test/mcp")
            self.assertNotIn("kta_pat_test_only", config_path.read_text(encoding="utf-8"))
            credentials_path = codex_dir / "kenning-guard-credentials.json"
            credentials = json.loads(credentials_path.read_text(encoding="utf-8"))
            self.assertEqual(credentials["mcp_url"], f"http://127.0.0.1:{self.server.server_port}/mcp")
            self.assertEqual(credentials["pat"], "kta_pat_test_only")
            self.assertEqual(credentials["tenant_id"], "tenant-test")
            self.assertEqual(credentials_path.stat().st_mode & 0o777, 0o600)
            self.assertIn(
                ".codex/kenning-guard-credentials.json",
                (project / ".gitignore").read_text(encoding="utf-8"),
            )
            bridge = codex_dir / "kenning-agent-guard-mcp.py"
            self.assertEqual(bridge.read_text(encoding="utf-8"), BRIDGE_SOURCE.read_text(encoding="utf-8"))
            self.assertEqual(bridge.stat().st_mode & 0o777, 0o700)
            clean_environment = {key: value for key, value in os.environ.items() if not key.startswith("KENNING_")}
            mcp_result = subprocess.run(
                ["python3", str(bridge)],
                input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n",
                cwd=project,
                env=clean_environment,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(mcp_result.returncode, 0, mcp_result.stderr)
            self.assertEqual(json.loads(mcp_result.stdout)["result"]["serverInfo"]["name"], "kenning-agent-guard")
            mcp_requests = [item for item in self.server.requests if item["path"] == "/mcp"]
            self.assertEqual(mcp_requests[-1]["headers"]["Authorization"], "Bearer kta_pat_test_only")
            self.assertEqual(mcp_requests[-1]["headers"]["X-Kenning-Tenant-Id"], "tenant-test")
            codex = shutil.which("codex")
            if codex:
                codex_config = subprocess.run(
                    [codex, "mcp", "get", "kenning-agent-guard"],
                    cwd=project,
                    env={**self.environment, "CODEX_HOME": str(codex_dir)},
                    text=True,
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(codex_config.returncode, 0, codex_config.stdout + codex_config.stderr)
                self.assertIn("kenning-agent-guard", codex_config.stdout)

            hooks = json.loads((codex_dir / "hooks.json").read_text(encoding="utf-8"))["hooks"]
            self.assertIn("echo unrelated", json.dumps(hooks))
            self.assertTrue(any("kenning-guard-hook.py" in json.dumps(group) for group in hooks["PreToolUse"]))
            self.assertTrue(any("kenning-guard-hook.py" in json.dumps(group) for group in hooks["PostToolUse"]))
            self.assertEqual((codex_dir / "kenning-guard-hook.py").read_text(encoding="utf-8"), HOOK_SOURCE.read_text(encoding="utf-8"))
            self.assertEqual((codex_dir / "kenning-guard-hook.py").stat().st_mode & 0o777, 0o700)
            self.assertNotIn("kta_pat_test_only", (codex_dir / "kenning-guard-hook.py").read_text(encoding="utf-8"))

            target = project / "tomato"
            target.mkdir()
            clean_environment = {key: value for key, value in os.environ.items() if not key.startswith("KENNING_")}
            command = f"rmdir {target}"
            blocked_input = {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec_command",
                "tool_use_id": "blocked-call",
                "cwd": str(project),
                "tool_input": {"cmd": command, "workdir": str(project)},
            }
            hook = codex_dir / "kenning-guard-hook.py"
            blocked = self.run_hook(hook, blocked_input, environment=clean_environment)
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
            blocked_result = json.loads(blocked.stdout)
            self.assertEqual(blocked_result["decision"], "block")
            self.assertIn(self.server.approval_id, blocked_result["reason"])
            self.assertTrue(target.exists(), "the destructive command ran before approval")

            retry = self.run_hook(
                hook,
                {**blocked_input, "tool_use_id": "approved-call"},
                environment=clean_environment,
            )
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertEqual(retry.stdout, "")
            target.rmdir()
            outcome = self.run_hook(
                hook,
                {**blocked_input, "hook_event_name": "PostToolUse", "tool_use_id": "approved-call"},
                environment=clean_environment,
            )
            self.assertEqual(outcome.returncode, 0, outcome.stderr)
            self.assertEqual(outcome.stdout, "")

            evaluations = [item for item in self.server.requests if item["path"] == "/v1/actions/evaluate"]
            self.assertGreaterEqual(len(evaluations), 3)  # installer check, blocked call, exact retry
            retry_request = evaluations[-1]["body"]
            self.assertEqual(retry_request["approval_id"], self.server.approval_id)
            self.assertEqual(retry_request["action_hash"], self.server.approved_hash)
            self.assertEqual(retry_request["action"]["parameters"]["command"], command)
            outcomes = [item for item in self.server.requests if item["path"].endswith("/outcome")]
            self.assertEqual(outcomes[-1]["body"]["status"], "success")

            sqlite_blocked = self.run_hook(
                hook,
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "exec_command",
                    "tool_use_id": "sqlite-blocked-call",
                    "cwd": str(project),
                    "tool_input": {"cmd": 'sqlite3 green.sqlite3 "DROP TABLE green;"', "workdir": str(project)},
                },
                environment=clean_environment,
            )
            self.assertEqual(sqlite_blocked.returncode, 0, sqlite_blocked.stderr)
            sqlite_result = json.loads(sqlite_blocked.stdout)
            self.assertEqual(sqlite_result["decision"], "block")
            self.assertIn(self.server.approval_id, sqlite_result["reason"])

            clean_environment = {key: value for key, value in os.environ.items() if not key.startswith("KENNING_")}
            uninstalled = self.run_installer(project, "--uninstall", environment=clean_environment)
            self.assertEqual(uninstalled.returncode, 0, uninstalled.stdout + uninstalled.stderr)
            self.assertFalse((project / "AGENTS.kenning.md").exists())
            self.assertFalse((codex_dir / "kenning-guard-hook.py").exists())
            self.assertFalse((codex_dir / "kenning-agent-guard-mcp.py").exists())
            self.assertFalse((codex_dir / "kenning-guard-credentials.json").exists())
            self.assertFalse((codex_dir / "kenning-guard-state.json").exists())
            self.assertFalse((project / ".gitignore").exists())
            final_config = tomllib.loads(config_path.read_text(encoding="utf-8"))
            self.assertNotIn("kenning-agent-guard", json.dumps(final_config))
            self.assertNotIn("AGENTS.kenning.md", final_config.get("project_doc_fallback_filenames", []))
            final_hooks = json.loads((codex_dir / "hooks.json").read_text(encoding="utf-8"))
            self.assertIn("echo unrelated", json.dumps(final_hooks))
            self.assertNotIn("kenning-guard-hook.py", json.dumps(final_hooks))
            final_json = json.loads((codex_dir / "config.json").read_text(encoding="utf-8"))
            self.assertIn("unrelated", final_json["mcpServers"])
            self.assertNotIn("kenning-agent-guard", json.dumps(final_json))
            self.assertTrue(list(codex_dir.glob("*.kenning-backup-*")))

    def test_installer_hook_matches_canonical_source(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        marker = "cat > \"$PROJECT_DIR/.codex/kenning-guard-hook.py\" <<'HOOK'\n"
        start = installer.index(marker) + len(marker)
        end = installer.index("\nHOOK", start)
        self.assertEqual(installer[start:end], HOOK_SOURCE.read_text(encoding="utf-8").rstrip("\n"))

    def test_installer_bridge_matches_canonical_source(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        marker = 'cat > "$PROJECT_DIR/.codex/kenning-agent-guard-mcp.py" <<\'MCP_BRIDGE\'\n'
        start = installer.index(marker) + len(marker)
        end = installer.index("\nMCP_BRIDGE", start)
        self.assertEqual(installer[start:end], BRIDGE_SOURCE.read_text(encoding="utf-8").rstrip("\n"))


if __name__ == "__main__":
    unittest.main()
