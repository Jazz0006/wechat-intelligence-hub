import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

import wechat_intelligence_hub as radar


class WeChatCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.app = self.root / "WeChat.app"
        self.plist = self.app / "Contents" / "Info.plist"
        self.plist.parent.mkdir(parents=True)
        self.cli = self.root / "wechat-cli"
        self.cli.write_bytes(b"fake-reader")
        self.state_dir = self.root / "compatibility"
        self.write_wechat_version("4.1.11", "269079", "4.1.11.23")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_windows_python_backend_keeps_chat_arguments_out_of_shell(self) -> None:
        engine = self.root / "reader/rion_wechat_reader.py"
        interpreter = engine.parent / "venv/Scripts/python.exe"
        interpreter.parent.mkdir(parents=True)
        interpreter.write_bytes(b"synthetic-runtime")
        chat = 'fictional & echo synthetic | example'
        completed = __import__("subprocess").CompletedProcess([], 0, '{"ok":true}', '')
        with mock.patch.object(radar.sys, "platform", "win32"), \
             mock.patch.object(radar.subprocess, "run", return_value=completed) as run:
            self.assertEqual(radar.run_json_command([str(engine), "timeline", chat]), {"ok": True})
        self.assertEqual(run.call_args.args[0], [str(interpreter), str(engine), "timeline", chat])
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_windows_batch_backends_are_rejected(self) -> None:
        with mock.patch.object(radar.sys, "platform", "win32"), \
             mock.patch.object(radar.subprocess, "run") as run:
            with self.assertRaises(SystemExit):
                radar.run_json_command(["reader.cmd", "timeline", "fictional & value"])
        run.assert_not_called()

    def write_wechat_version(self, version: str, build: str, bundle_version: str) -> None:
        with self.plist.open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleShortVersionString": version,
                    "CFBundleVersion": build,
                    "WeChatBundleVersion": bundle_version,
                },
                handle,
            )

    @staticmethod
    def successful_command(command: list[str]) -> dict:
        if command[-1] == "version":
            return {"data": {"version": "1.6.19"}}
        if "status" in command:
            return {
                "data": {
                    "status": {
                        "live_read_ok": True,
                        "readiness": "ready",
                        "capabilities": {"sessions": True, "timeline": True, "search": True},
                    }
                }
            }
        if "sessions" in command:
            return {
                "data": {
                    "sessions": [
                        {"username": "@placeholder_foldgroup", "chat_type": "folded"},
                        {"username": "private-secret-id", "display_name": "secret", "chat_type": "private"},
                    ]
                }
            }
        if "timeline" in command:
            media_flag = command.index("--include-media-paths")
            if command[media_flag + 1] != "false":
                raise AssertionError(command)
            return {"data": {"messages": [{"content": "secret-message-body"}]}}
        raise AssertionError(command)

    def run_check(self) -> dict:
        return radar.run_compatibility_check(
            str(self.cli),
            wechat_app_value=str(self.app),
            state_dir_value=str(self.state_dir),
            force=True,
        )

    def test_live_smoke_check_is_ready_and_does_not_store_chat_content(self) -> None:
        with mock.patch.object(radar, "run_json_command", side_effect=self.successful_command):
            report = self.run_check()

        self.assertEqual(report["result"], "ready")
        self.assertEqual(report["checks"]["timeline"]["count"], 1)
        saved = (self.state_dir / "latest.json").read_text(encoding="utf-8")
        self.assertNotIn("private-secret-id", saved)
        self.assertNotIn("secret-message-body", saved)

    def test_wechat_upgrade_is_recorded_and_retested(self) -> None:
        with mock.patch.object(radar, "run_json_command", side_effect=self.successful_command):
            first = self.run_check()
            self.write_wechat_version("4.1.12", "270000", "4.1.12.1")
            second = self.run_check()

        self.assertFalse(first["version_changed"])
        self.assertTrue(second["version_changed"])
        self.assertEqual(second["result"], "ready")
        history = list((self.state_dir / "history").glob("*.json"))
        self.assertEqual(len(history), 2)

    def test_reader_failure_blocks_live_workflows(self) -> None:
        def failing_command(command: list[str]) -> dict:
            if command[-1] == "version":
                return {"data": {"version": "1.6.19"}}
            if "status" in command:
                return {
                    "data": {
                        "status": {
                            "live_read_ok": True,
                            "readiness": "ready",
                            "capabilities": {"sessions": True, "timeline": True, "search": True},
                        }
                    }
                }
            if "sessions" in command:
                raise SystemExit("schema changed for wxid_private-secret")
            raise AssertionError(command)

        with mock.patch.object(radar, "run_json_command", side_effect=failing_command):
            report = self.run_check()

        self.assertEqual(report["result"], "blocked")
        self.assertFalse(report["checks"]["sessions"]["ok"])
        self.assertNotIn("wxid_private-secret", json.dumps(report, ensure_ascii=False))
        self.assertIn("db-search", report["next_action"])


if __name__ == "__main__":
    unittest.main()
