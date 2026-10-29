"""Windows CI checks use synthetic data only, never a WeChat installation."""

import json
from pathlib import Path
import platform
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rion_wechat_reader as reader


@unittest.skipUnless(platform.system() == "Windows", "native Windows only")
class NativeWindowsTests(unittest.TestCase):
    def test_private_json_acl_and_unicode_path(self):
        with reader.private_temporary_directory(prefix="reader-native-") as directory:
            path = Path(directory) / "中文 ' 文件.json"
            reader.secure_write_json(path, {"synthetic": True})
            self.assertTrue(reader.safe_mode(path))
            self.assertEqual(reader.load_json(path), {"synthetic": True})

    def test_utf16_material_decrypts_synthetic_database(self):
        driver, _ = reader.sqlcipher_driver()
        self.assertIsNotNone(driver, "CI must install SQLCipher, not skip encryption validation")
        with reader.private_temporary_directory(prefix="reader-native-") as directory:
            root = Path(directory)
            database = root / "消息.db"
            key = "ab" * 32
            conn = driver.connect(str(database))
            try:
                conn.execute("PRAGMA key = \"x'" + key + "'\"")
                conn.execute("CREATE TABLE synthetic(value TEXT)")
                conn.commit()
            finally:
                conn.close()
            material = root / "input.json"
            payload = {database.name: {"raw_key": "x'" + key + "'"}}
            reader.secure_write_json(material, payload)
            material.write_text(json.dumps(payload), encoding="utf-16")
            result = reader.import_access_bundle(material, root, root / "normalized.json",
                                                 force=False, verify=True, max_files=10)
            self.assertEqual(result["verification"]["matched_database_count"], 1)
            self.assertEqual(result["verification"]["unrecognized_readable_count"], 1)
            self.assertNotIn(key, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
