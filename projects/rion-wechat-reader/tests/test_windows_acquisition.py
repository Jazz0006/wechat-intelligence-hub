"""Acquisition boundaries and real SQLCipher fixtures; never access WeChat."""
import contextlib
import ctypes
import io
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rion_wechat_access as access
import rion_wechat_reader as reader
import rion_wechat_windows as win


def counts():
    return dict(bytes_attempted=0, bytes_read=0, unreadable_blocks=0,
                candidates_checked=0, scan_truncated=False)


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        if platform.system() == "Windows":
            self.assertTrue(reader.windows_private_acl(self.root, initialize=True))
        else:
            self.root.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, name="contact/contact.db", key="ab" * 32, password=None):
        driver, _ = reader.sqlcipher_driver()
        if driver is None:
            self.skipTest("SQLCipher runtime required for independent encrypted fixture")
        storage = self.root / "db_storage"
        for folder in ("contact", "session", "message"):
            (storage / folder).mkdir(parents=True, exist_ok=True)
        path = storage / name
        conn = driver.connect(str(path))
        try:
            conn.execute("PRAGMA key = " + ("'" + password + "'" if password else '"x\'' + key + '\'"'))
            conn.execute("CREATE TABLE synthetic(value TEXT)")
            conn.execute("INSERT INTO synthetic VALUES ('fictional-only')")
            conn.commit()
        finally:
            conn.close()
        return storage, path.read_bytes()[:4096]

    def plan(self, identity=None):
        self.fixture()
        root, pages = win.database_pages(self.root)
        plan = dict(schema_version=1, created_at=time.time(), identity=identity or {"pid": 123},
                    database_root=str(root), database_pages=win.page_fingerprints(root, pages),
                    profile=None, profile_review_required=False)
        path = self.root / "plan.json"
        win.write_private_json(path, plan)
        return path, plan

    def test_raw_candidate_must_open_real_sqlcipher_page(self):
        _, page = self.fixture()
        key = bytes.fromhex("ab" * 32)
        self.assertTrue(win.valid_raw_key(key, page))
        self.assertFalse(win.valid_raw_key(b"\x00" * 32, page))
        self.assertFalse(win.valid_raw_key(key, page[:-1] + bytes([page[-1] ^ 1])))

    def test_each_database_salt_is_verified_independently(self):
        storage, first = self.fixture()
        _, second = self.fixture("message/message_0.db", key="cd" * 32)
        data = ("x'" + "ab" * 32 + first[:16].hex() + "' x'" + "cd" * 32 + second[:16].hex() + "'").encode()
        pages = [(storage / "contact/contact.db", first), (storage / "message/message_0.db", second)]
        result = win.scan([data], pages, None, time.monotonic() + 5, 20, counts())
        self.assertEqual(result, {first[:16].hex(): "ab" * 32, second[:16].hex(): "cd" * 32})

    def test_wrong_embedded_salt_never_matches(self):
        root, page = self.fixture()
        result = win.scan([("x'" + "ab" * 32 + "00" * 16 + "'").encode()],
                          [(root / "contact/contact.db", page)], None, time.monotonic() + 3, 10, counts())
        self.assertEqual(result, {})

    def test_profile_transforms_password_once_then_derives_per_salt(self):
        root, page = self.fixture(password="P" * 32)
        rule = dict(pattern_hex=b"TESTONLY".hex(), offset=8, length=32, mode="password", xor_hex="55")
        profile = {"rules": [rule]}
        data = b"TESTONLY" + bytes(value ^ 0x55 for value in b"P" * 32)
        result = win.scan([data], [(root / "contact/contact.db", page)], profile,
                          time.monotonic() + 5, 4, counts())
        self.assertEqual(len(result), 1)
        self.assertTrue(win.valid_raw_key(bytes.fromhex(next(iter(result.values()))), page))

    def test_budget_and_deadline_are_fail_closed(self):
        root, page = self.fixture()
        diagnostics = counts()
        data = ("x'" + "ab" * 32 + "'").encode()
        found = win.scan([data], [(root / "contact/contact.db", page)], None, 0, 10, diagnostics)
        self.assertEqual(found, {})
        self.assertTrue(diagnostics["scan_truncated"])
        diagnostics = counts()
        wrong = ("x'" + "00" * 32 + "' ").encode()
        found = win.scan([wrong + data], [(root / "contact/contact.db", page)], None,
                         time.monotonic() + 3, 1, diagnostics)
        self.assertEqual(found, {})
        self.assertEqual(diagnostics["candidates_checked"], 1)

    def test_output_publication_never_overwrites(self):
        path = self.root / "record.json"
        win.write_private_json(path, {"existing": True})
        with self.assertRaisesRegex(win.WindowsAccessError, "not_overwritten"):
            win.write_private_json(path, {"existing": False})
        self.assertEqual(reader.load_json(path), {"existing": True})
        self.assertEqual(list(self.root.glob(".windows-stage-*")), [])

    def test_profile_requires_exact_active_dll_hash_and_version(self):
        path = self.root / "profile.json"
        path.write_text(json.dumps({"schema_version": 1, "dll_sha256": "a" * 64,
                                   "dll_version": "4.1.0.1", "rules": []}))
        with self.assertRaisesRegex(win.WindowsAccessError, "build_mismatch"):
            win.load_profile(path, {"dll_sha256": "b" * 64, "dll_version": "4.1.0.1"})

    def test_expired_plan_rejected_before_process_open(self):
        path = self.root / "old.json"
        win.write_private_json(path, {"schema_version": 1, "created_at": time.time() - 1000})
        with mock.patch.object(win, "require_windows"), mock.patch.object(win, "WindowsProcess") as process:
            with self.assertRaisesRegex(win.WindowsAccessError, "expired"):
                win.acquire(path, True)
            process.assert_not_called()

    def test_consent_required_before_plan_or_process_is_read(self):
        with mock.patch.object(win, "require_windows"), mock.patch.object(win, "load_plan") as load:
            with self.assertRaisesRegex(win.WindowsAccessError, "confirmation_required"):
                win.acquire(self.root / "missing.json", False)
            load.assert_not_called()

    def test_prepare_never_scans_memory(self):
        self.fixture()
        identity = {"pid": 123, "dll_version": "4.1.0.1"}
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.identity.return_value = identity
        with mock.patch.object(win, "require_windows"), mock.patch.object(win, "WindowsProcess", return_value=process):
            report = win.prepare(123, self.root, self.root / "plan.json")
        process.blocks.assert_not_called()
        self.assertEqual(report["state"], "authorization_required")
        self.assertFalse(report["process_memory_read"])

    def test_changed_process_cannot_be_scanned(self):
        _, plan = self.plan()
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.identity.return_value = {"pid": 123, "created": "replacement"}
        with mock.patch.object(win, "WindowsProcess", return_value=process):
            with self.assertRaisesRegex(win.WindowsAccessError, "process_or_build_changed"):
                win._capture(plan, self.root, 5, 1, 10)
        process.blocks.assert_not_called()

    def test_changed_process_after_scan_cannot_publish_keys(self):
        _, plan = self.plan()
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.identity.side_effect = [plan["identity"], {"pid": 123, "created": "replacement"}]
        process.blocks.return_value = [("x'" + "ab" * 32 + "'").encode()]
        with mock.patch.object(win, "WindowsProcess", return_value=process):
            with self.assertRaisesRegex(win.WindowsAccessError, "process_or_build_changed"):
                win._capture(plan, self.root, 5, 1, 10)
        self.assertFalse((self.root / "verified-candidates.json").exists())

    def test_same_user_token_is_required_before_any_memory_access(self):
        kernel = mock.Mock()
        kernel.OpenProcess.return_value = 99
        kernel.GetCurrentProcess.return_value = -1
        with mock.patch.object(win, "require_windows"), \
             mock.patch.object(win.C, "WinDLL", create=True, return_value=kernel), \
             mock.patch.object(win.WindowsProcess, "_bind"), \
             mock.patch.object(win.WindowsProcess, "_sid", side_effect=["other-owner", "current-owner"]):
            with self.assertRaisesRegex(win.WindowsAccessError, "owner_mismatch"):
                win.WindowsProcess(123, read_memory=True)
        kernel.OpenProcess.assert_called_once_with(0x0410, False, 123)
        kernel.ReadProcessMemory.assert_not_called()
        kernel.CloseHandle.assert_called_once_with(99)

    def test_partial_coverage_remains_partial(self):
        _, plan = self.plan()
        self.fixture("message/message_0.db", key="cd" * 32)
        root, pages = win.database_pages(Path(plan["database_root"]))
        plan["database_pages"] = win.page_fingerprints(root, pages)
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.identity.return_value = plan["identity"]
        process.blocks.return_value = [("x'" + "ab" * 32 + "'").encode()]
        with mock.patch.object(win, "WindowsProcess", return_value=process):
            result = win._capture(plan, self.root, 10, 1, 10)
        self.assertEqual(result["state"], "partial_key_coverage")
        self.assertEqual(result["verified_database_count"], 1)
        self.assertEqual(result["database_count"], 2)
        self.assertFalse(result["configured"])

    def test_failed_independent_validation_removes_candidate_material(self):
        _, plan = self.plan()
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.identity.return_value = plan["identity"]
        process.blocks.return_value = [("x'" + "ab" * 32 + "'").encode()]
        with mock.patch.object(win, "WindowsProcess", return_value=process), \
             mock.patch.object(reader, "import_access_bundle", side_effect=reader.ReaderError("secret-do-not-print", "access_bundle_not_compatible")):
            win._capture_worker(plan, str(self.root), 10, 1, 10)
        self.assertFalse((self.root / "verified-candidates.json").exists())
        result = (self.root / "result.json").read_text()
        self.assertNotIn("secret-do-not-print", result)
        self.assertNotIn("ab" * 32, result)
        self.assertEqual(json.loads(result)["error_code"], "access_bundle_not_compatible")

    def test_unsafe_plan_acl_stops_before_scanner(self):
        plan, _ = self.plan()
        with mock.patch.object(win, "require_windows"), mock.patch.object(reader, "safe_mode", return_value=False), \
             mock.patch.object(win.MP, "get_context") as start:
            with self.assertRaisesRegex(win.WindowsAccessError, "unsafe_plan"):
                win.acquire(plan, True)
        start.assert_not_called()

    def test_sqlcipher_validation_and_redacted_result(self):
        _, plan = self.plan()
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.identity.return_value = plan["identity"]
        process.blocks.return_value = [("x'" + "ab" * 32 + "'").encode()]
        with mock.patch.object(win, "WindowsProcess", return_value=process):
            result = win._capture(plan, self.root, 10, 1, 10)
        self.assertEqual(result["state"], "material_verified")
        self.assertEqual(result["verified_database_count"], 1)
        self.assertNotIn("ab" * 32, json.dumps(result))
        self.assertFalse(result["configured"])
        normalized = reader.load_json(self.root / "reader-keys.json")
        self.assertTrue(normalized["salt_keys"])

    def test_timeout_terminates_only_owned_scanner(self):
        plan, _ = self.plan()
        worker = mock.Mock()
        worker.is_alive.side_effect = [True, True]
        context = mock.Mock()
        context.Process.return_value = worker
        with mock.patch.object(win, "require_windows"), \
             mock.patch.object(reader, "windows_private_acl", return_value=True), \
             mock.patch.object(win.MP, "get_context", return_value=context):
            result = win.acquire(plan, True, timeout=5)
        self.assertEqual(result["state"], "scan_timeout_review_required")
        worker.terminate.assert_called_once()
        worker.kill.assert_called_once()
        with mock.patch.object(win, "require_windows"):
            with self.assertRaisesRegex(win.WindowsAccessError, "attempt_exists"):
                win.acquire(plan, True)

    def test_cli_wrong_host_returns_fixed_error_without_traceback(self):
        with mock.patch.object(win.platform, "system", return_value="Darwin"), contextlib.redirect_stdout(io.StringIO()) as output:
            code = access.main(["windows-acquire", "--plan-file", str(self.root / "missing"), "--confirm-process-read"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], "windows_host_required")
        self.assertNotIn(str(self.root), output.getvalue())

    @unittest.skipIf(platform.system() == "Windows", "symlink creation may require Windows privileges")
    def test_symlink_account_rejected(self):
        storage, _ = self.fixture()
        link = self.root / "alias"
        link.symlink_to(storage, target_is_directory=True)
        with self.assertRaisesRegex(win.WindowsAccessError, "reparse"):
            win.database_pages(link)


@unittest.skipUnless(platform.system() == "Windows", "real Win32 API fixture, no WeChat")
class NativeProcessTests(unittest.TestCase):
    def test_owned_memory_with_64_bit_api_and_token_check(self):
        value = ctypes.create_string_buffer(b"fictional-fixture-only")
        with win.WindowsProcess(os.getpid(), read_memory=True) as process:
            buffer, count = ctypes.create_string_buffer(len(value)), ctypes.c_size_t()
            self.assertTrue(process.kernel.ReadProcessMemory(process.handle, ctypes.addressof(value), buffer,
                                                           len(buffer), ctypes.byref(count)))
            self.assertEqual(buffer.raw, value.raw)
            self.assertEqual(ctypes.sizeof(win.MemoryInfo), 48)
            with self.assertRaises(win.WindowsAccessError):
                process.identity()  # the test Python process is never accepted as WeChat


if __name__ == "__main__":
    unittest.main()
