#!/usr/bin/env python3
"""Unit tests: fail closed on wrong dex, wrong module, and preserve byte identity."""
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
import hashlib
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import repack_dexonly

class DexOnlyTests(unittest.TestCase):
    def setUp(self):
        t=TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d=Path(t.name)
        self.original=self.d/"official.zip"
        self.v308=self.d/"v308.zip"
        self.out=self.d/"out.zip"
        self.orig={
            "module.prop":b"id=tricky_store\nname=AlwaysStrong [Inject]\nversion=v1.0.5\nversionCode=105\nupdateJson=https://example.test/foo.json\n",
            "engine.sh":b"ENGINE=inject\n",
            "tee_classes.dex":b"old dex",
            "service.sh":b"auto_keybox=1; if as_on auto_keybox; then true; fi\n",
            "keybox_fetch.sh":b"#!/bin/sh\n",
            "attest.sh":b"#!/bin/sh\n",
            "lib/arm64-v8a/libTEESimulator.so":b"old binary",
            "zygisk/arm64-v8a.so":b"untouched inject module",
            "keybox.xml":b"test fixture only",
        }
        self.eng={"classes.dex":b"new v308 dex"}
        self.create(self.original,self.orig)
        self.create(self.v308,self.eng)
        self.old=repack_dexonly.EXPECTED_PR76_DEX
        repack_dexonly.EXPECTED_PR76_DEX=hashlib.sha256(self.eng["classes.dex"]).hexdigest()
        self.addCleanup(lambda:setattr(repack_dexonly,"EXPECTED_PR76_DEX",self.old))

    @staticmethod
    def create(file,items):
        with ZipFile(file,"w") as z:
            for k,v in items.items():z.writestr(k,v)

    def test_only_one_existing_file_changed(self):
        info=repack_dexonly.repack(self.original,self.v308,self.out)
        self.assertEqual(info["changed_original_file"],"tee_classes.dex")
        with ZipFile(self.out) as z:
            self.assertIsNone(z.testzip())
            for k,content in self.orig.items():
                self.assertEqual(z.read(k),self.eng["classes.dex"] if k=="tee_classes.dex" else content)
            self.assertEqual(len(z.namelist()),len(self.orig)+1)

    def test_wrong_dex_rejected(self):
        repack_dexonly.EXPECTED_PR76_DEX="f"*64
        with self.assertRaisesRegex(ValueError,"Wrong v308 bytecode"):repack_dexonly.repack(self.original,self.v308,self.out)

    def test_noninject_rejected(self):
        self.orig["module.prop"]=self.orig["module.prop"].replace(b"AlwaysStrong [Inject]",b"AlwaysStrong")
        self.create(self.original,self.orig)
        with self.assertRaisesRegex(ValueError,"Must be AlwaysStrong"):repack_dexonly.repack(self.original,self.v308,self.out)

    def test_missing_keybox_refresh_rejected(self):
        self.orig["service.sh"]=b"no auto keybox"
        self.create(self.original,self.orig)
        with self.assertRaisesRegex(ValueError,"Automatic keybox check missing"):repack_dexonly.repack(self.original,self.v308,self.out)

    def test_refuse_in_place(self):
        with self.assertRaisesRegex(ValueError,"Output must not overwrite"):repack_dexonly.repack(self.original,self.v308,self.original)

if __name__=="__main__":
    unittest.main()
