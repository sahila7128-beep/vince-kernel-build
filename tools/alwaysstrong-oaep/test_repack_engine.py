#!/usr/bin/env python3
"""Offline unit tests for the ZIP repacker; no device, root, network or keys."""
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).parent))
from repack_engine import repack


def make_zip(file: Path, entries: dict[str, bytes]) -> None:
    with ZipFile(file, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)


class RepackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.original, self.engine, self.output = (
            root / "AlwaysStrong-v1.0.5-inject.zip",
            root / "TEE-Release.zip",
            root / "Vince-TRIAL.zip",
        )
        self.orig_entries = {
            "module.prop": (b"id=tricky_store\nname=AlwaysStrong [Inject]\n"
                            b"version=v1.0.5\nversionCode=105\n"
                            b"updateJson=https://example.invalid/update\n"),
            "engine.sh": b"ENGINE=inject\n",
            "attest.sh": b"#!/system/bin/sh\n",
            "tee_classes.dex": b"original-TEE-bytecode",
            "classes.dex": b"original-PIF-bytecode",
            "lib/arm64-v8a/libTEE.so": b"original-TEE-native",
            "zygisk/arm64-v8a.so": b"original-PIF-zygisk",
            "keybox.xml": b"placeholder-public-fixture-not-real-keys",
            "customize.sh": b"echo untouched\n",
        }
        self.eng_entries = {
            "classes.dex": b"patched-TEE-bytecode",
            "lib/arm64-v8a/libTEE.so": b"patched-TEE-native",
            "module.prop": b"id=standalone_tee\n",
        }
        make_zip(self.original, self.orig_entries)
        make_zip(self.engine, self.eng_entries)

    def test_exact_replacements_and_other_files_unchanged(self):
        info = repack(self.original, self.engine, self.output)
        self.assertTrue(self.output.is_file())
        self.assertIn("tee_classes.dex", info["replaced_entries"])
        with ZipFile(self.output) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(z.read("tee_classes.dex"), b"patched-TEE-bytecode")
            self.assertEqual(z.read("lib/arm64-v8a/libTEE.so"), b"patched-TEE-native")
            for filename in ("classes.dex", "zygisk/arm64-v8a.so",
                             "keybox.xml", "customize.sh", "engine.sh"):
                self.assertEqual(z.read(filename), self.orig_entries[filename])
            self.assertIn(b"OAEP TRIAL", z.read("module.prop"))
            self.assertNotIn(b"updateJson=", z.read("module.prop"))
            self.assertEqual(len(z.namelist()), len(self.orig_entries) + 1)

    def test_rejects_non_inject(self):
        self.orig_entries["module.prop"] = (
            self.orig_entries["module.prop"].replace(b"[Inject]", b"")
        )
        make_zip(self.original, self.orig_entries)
        with self.assertRaisesRegex(ValueError, "ORIGINAL AlwaysStrong"):
            repack(self.original, self.engine, self.output)

    def test_rejects_unknown_engine_library(self):
        self.eng_entries["lib/arm64-v8a/libNotInOriginal.so"] = b"extra"
        make_zip(self.engine, self.eng_entries)
        with self.assertRaisesRegex(ValueError, "lacks expected engine library"):
            repack(self.original, self.engine, self.output)

    def test_rejects_output_equal_to_input(self):
        with self.assertRaisesRegex(ValueError, "Output path must differ"):
            repack(self.original, self.engine, self.original)

    def test_rejects_path_traversal(self):
        self.eng_entries["../escape"] = b"bad"
        make_zip(self.engine, self.eng_entries)
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            repack(self.original, self.engine, self.output)


if __name__ == "__main__":
    unittest.main()
