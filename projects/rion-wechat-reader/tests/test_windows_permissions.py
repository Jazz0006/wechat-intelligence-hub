import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rion_wechat_reader as reader
import rion_wechat_access as access


class WindowsPermissionsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.path = self.root / "keys.json"
        self.path.touch()
        self.platform = mock.patch.object(reader.platform, "system", return_value="Windows")
        self.platform.start()

    def tearDown(self):
        self.platform.stop()
        self.directory.cleanup()

    def check(self, stdout=b"SAFE\n", code=0):
        with mock.patch.object(reader.shutil, "which", return_value="pwsh.exe"), \
             mock.patch.object(reader.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], code, stdout, b"")) as run:
            result = reader.safe_mode(self.path)
        return result, run

    def test_acl_passes_even_when_posix_mode_is_broad(self):
        self.path.chmod(0o666)
        result, run = self.check()
        self.assertTrue(result)
        options = run.call_args.kwargs
        self.assertEqual(options["timeout"], 15)
        self.assertEqual(options["env"]["RION_READER_ACL_INITIALIZE"], "0")

    def test_acl_fails_even_when_posix_mode_is_private(self):
        self.path.chmod(0o600)
        self.assertFalse(self.check(b"UNSAFE")[0])

    def test_nonzero_exit_and_extra_output_fail_closed(self):
        for stdout, code in [(b"SAFE", 1), (b"SAFE\nextra", 0), (b"", 0)]:
            with self.subTest(stdout=stdout, code=code):
                self.assertFalse(self.check(stdout, code)[0])

    def test_missing_powershell_does_not_run(self):
        with mock.patch.object(reader.shutil, "which", return_value=None), \
             mock.patch.object(reader.subprocess, "run") as run:
            self.assertFalse(reader.safe_mode(self.path))
        run.assert_not_called()

    def test_timeout_and_os_error_fail_closed(self):
        for error in [subprocess.TimeoutExpired("pwsh", 15), OSError("unavailable")]:
            with mock.patch.object(reader.shutil, "which", return_value="pwsh.exe"), \
                 mock.patch.object(reader.subprocess, "run", side_effect=error):
                self.assertFalse(reader.safe_mode(self.path))

    def test_path_is_passed_as_data_not_powershell_source(self):
        self.path = self.root / "中文 ' ; Write-Host unsafe.json"
        self.path.touch()
        _, run = self.check()
        args = run.call_args.args[0]
        self.assertNotIn(str(self.path), args[-1])
        self.assertEqual(run.call_args.kwargs["env"]["RION_READER_ACL_PATH"], str(self.path))
        self.assertIn("Get-Acl -LiteralPath", args[-1])
        self.assertIn("ReparsePoint", args[-1])

    def test_permission_help_is_windows_specific(self):
        self.assertIn("ACL", reader.permission_help())
        self.assertNotIn("chmod", reader.permission_help())

    def test_existing_parent_is_not_repermissioned(self):
        with mock.patch.object(reader, "windows_private_acl", return_value=False) as acl:
            with self.assertRaises(reader.ReaderError):
                reader.secure_write_json(self.root / "output.json", {"test": True})
        acl.assert_called_once_with(self.root, initialize=False)
        self.assertFalse((self.root / "output.json").exists())

    def test_new_parent_and_empty_temp_protected_before_secret_write(self):
        path = self.root / "private" / "output.json"
        observed = []

        def acl(resource, *, initialize=False):
            observed.append((resource, initialize))
            if resource.is_file():
                self.assertEqual(resource.read_bytes(), b"")
            return True

        with mock.patch.object(reader, "windows_private_acl", side_effect=acl):
            reader.secure_write_json(path, {"test": "private-fixture"})
        self.assertTrue(observed[0][1])
        self.assertTrue(observed[1][1])
        self.assertEqual(json.loads(path.read_text()), {"test": "private-fixture"})

    def test_failed_temp_protection_keeps_existing_output(self):
        self.path.write_text("original")
        with mock.patch.object(reader, "windows_private_acl", side_effect=[True, False]):
            with self.assertRaises(reader.ReaderError):
                reader.secure_write_json(self.path, {"test": True}, force=True)
        self.assertEqual(self.path.read_text(), "original")
        self.assertEqual(list(self.root.glob("keys.json.*")), [])

    def test_windows_missing_material_routes_without_acquisition(self):
        args = SimpleNamespace(config=self.root / "new-config.json", source=None,
                               database_root=self.root, max_files=10)
        plan = {"state": "needs_access", "live_database_read_ok": False,
                "scope": {}, "counts": {}, "performed": {}, "next_actions": []}
        with mock.patch.object(reader, "access_plan", return_value=plan), \
             mock.patch.object(reader, "load_json", return_value={}), \
             mock.patch.object(access.os.path, "lexists", return_value=False), \
             mock.patch.dict(access.os.environ, {"RION_WECHAT_READER_KEYS": ""}), \
             mock.patch.object(access, "run", side_effect=AssertionError("no acquisition")):
            result = access.onboard(args)
        self.assertEqual(result["state"], "acquisition_platform_not_supported")
        self.assertEqual(result["windows_route"]["status"], "community_report_not_integrated")
        self.assertFalse(result["windows_route"]["acquisition_performed"])

    def test_preview_directory_protected_before_yield(self):
        seen = []
        with mock.patch.object(reader, "windows_private_acl", side_effect=lambda p, **kw: seen.append((p, kw)) or True):
            with reader.private_temporary_directory(prefix="fixture-") as directory:
                self.assertEqual(seen, [(Path(directory), {"initialize": True})])
                self.assertTrue(Path(directory).exists())
        self.assertFalse(Path(directory).exists())

    def test_failed_preview_acl_never_yields(self):
        with mock.patch.object(reader, "windows_private_acl", return_value=False):
            with self.assertRaises(reader.ReaderError):
                with reader.private_temporary_directory(prefix="fixture-"):
                    self.fail("must not expose an unprotected temporary directory")

    def test_connect_checks_acl_not_posix_mode(self):
        config = self.root / "config.json"
        self.root.chmod(0o755)
        observed = []
        with mock.patch.object(reader, "windows_private_acl", side_effect=lambda p, **kw: observed.append((p, kw)) or True), \
             mock.patch.object(reader, "access_plan", return_value={"state": "partial", "counts": {}}):
            result = access.connect(None, self.root, config)
        self.assertEqual(result["state"], "partial")
        self.assertFalse(config.exists())
        self.assertIn((self.root, {"initialize": False}), observed)
        self.assertTrue(any(p.name.startswith("verified-access-") and kw.get("initialize") for p, kw in observed))

    def test_connect_rejects_bad_acl_without_changing_existing_parent(self):
        config = self.root / "config.json"
        with mock.patch.object(reader, "windows_private_acl", return_value=False) as acl:
            with self.assertRaises(reader.ReaderError):
                access.connect(None, self.root, config)
        acl.assert_called_once_with(self.root, initialize=False)
        self.assertFalse(config.exists())


if __name__ == "__main__":
    unittest.main()
