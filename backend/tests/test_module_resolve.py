import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.services.module_resolve import find_local_module, local_module_candidates, resolve_audit_module
from backend.services.patch_resolver import PatchResolveError, sanitize_filename


class ModuleNameTests(unittest.TestCase):
    def test_sanitize_ok(self):
        self.assertEqual(sanitize_filename("Netio.SYS"), "netio.sys")
        self.assertEqual(sanitize_filename(r"C:\Windows\System32\ntoskrnl.exe"), "ntoskrnl.exe")

    def test_sanitize_rejects_junk(self):
        with self.assertRaises(PatchResolveError):
            sanitize_filename("https://evil.example/x.sys")
        with self.assertRaises(PatchResolveError):
            sanitize_filename("foo.txt")


class LocalModuleTests(unittest.TestCase):
    def test_finds_beside_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "afd.sys"
            other = Path(tmp) / "netio.sys"
            sample.write_bytes(b"MZ" + b"\x00" * 300)
            other.write_bytes(b"MZ" + b"\x00" * 300)
            hit = find_local_module("netio.sys", sample)
            self.assertEqual(hit.resolve(), other.resolve())

    def test_candidates_include_drivers_dir(self):
        names = [p.name.lower() for p in local_module_candidates("fltmgr.sys")]
        self.assertIn("fltmgr.sys", names)

    def test_resolve_copies_local_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            work = Path(tmp) / "work"
            src_dir.mkdir()
            sample = src_dir / "afd.sys"
            dep = src_dir / "netio.sys"
            sample.write_bytes(b"MZ" + b"\x00" * 300)
            dep.write_bytes(b"MZ" + b"\x00" * 300)
            with patch("backend.services.module_resolve.extract_pe", return_value={"original_filename": "netio.sys", "file_version": "10.0.26100.1"}), patch(
                "backend.services.module_resolve.fetch_pdb", side_effect=RuntimeError("no pdb")
            ), patch(
                "backend.services.module_resolve.pe_import_table", return_value={"ntoskrnl.exe": ["ExAllocatePool2"]}
            ), patch(
                "backend.services.module_resolve.fetch_versioned_binary"
            ) as dl:
                rec = resolve_audit_module("netio.sys", work=work, sample_path=sample)
                self.assertEqual(rec["source"], "local")
                self.assertTrue(Path(rec["path"]).is_file())
                self.assertEqual(rec["imports"]["ntoskrnl.exe"], ["ExAllocatePool2"])
                resolve_audit_module("netio.sys", work=work, sample_path=sample)
                dl.assert_not_called()
