import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare", HERE / "prepare_candidate.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparationTests(unittest.TestCase):
    def test_patch_matches_pinned_manifest(self):
        manifest = json.loads((HERE / "candidate.json").read_text())
        self.assertEqual(hashlib.sha256((HERE / manifest["patch"]).read_bytes()).hexdigest(),
                         manifest["patch_sha256"])
        self.assertFalse(manifest["fresh_wechat_acquisition_verified"])
        self.assertFalse(manifest["privileged_launch_verified"])

    def archive(self, root, name, kind=tarfile.REGTYPE):
        path = root / "archive.tar"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = "outside"
            info.size = 3 if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(b"abc") if info.size else None)
        return path

    def test_reject_unsafe_archive_entries(self):
        for name, kind in [("../outside", tarfile.REGTYPE), ("/tmp/outside", tarfile.REGTYPE),
                           (".git/config", tarfile.REGTYPE), ("link", tarfile.SYMTYPE),
                           ("hardlink", tarfile.LNKTYPE), ("device", tarfile.CHRTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                with self.assertRaises(ValueError):
                    prepare.unpack(self.archive(root, name, kind), root / "source")
                self.assertFalse((root / "source").exists())

    def test_regular_file_extracts_without_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = self.archive(root, "cmd/sample.txt")
            destination = root / "source"
            destination.mkdir()
            prepare.unpack(archive, destination)
            self.assertEqual((destination / "cmd/sample.txt").read_text(), "abc")
            with self.assertRaises(FileExistsError):
                prepare.unpack(archive, destination)


if __name__ == "__main__":
    unittest.main()
