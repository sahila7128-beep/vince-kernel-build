"""Fail-closed regression tests for preserving actual Android Keymaster operations."""
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parent))

import patch_hardware_keys as patcher
import repack_hardware_keys as repacker


class TestSourcePatch(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        target=self.root/patcher.REL
        target.parent.mkdir(parents=True)
        self.original="""fun handleGenerateKey() {
                val parsedParams = KeyMintAttestation(params)
                val isAttestKeyRequest = parsedParams.isAttestKey()
                val hasDeviceIdAttestation = false
                ConfigurationManager.shouldGenerate(callingUid)
""" + patcher.ANCHOR + """
                doSoftwareKeyGen()
                AttestationPatcher.patchCertificateChain()
}"""
        target.write_text(self.original)
        cfg=self.root/"app/src/main/java/org/matrix/TEESimulator/config/ConfigurationManager.kt"
        cfg.parent.mkdir(parents=True)
        cfg.write_text("if (DeviceAttestationService.isTeeFunctional) Mode.PATCH else Mode.GENERATE")

    def test_patch_preserves_original_dispatch_and_injects_guard(self):
        hashv=patcher.patch(self.root)
        src=(self.root/patcher.REL).read_text()
        self.assertEqual(hashlib.sha256(src.encode()).hexdigest(),hashv)
        self.assertIn("VINCE_PASS_NON_ATTESTED_KEY_TO_HARDWARE",src)
        self.assertIn("cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))",src)
        self.assertLess(src.index("cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))"),src.index("VINCE_PASS_NON_ATTESTED_KEY_TO_HARDWARE"))
        self.assertLess(src.index("VINCE_PASS_NON_ATTESTED_KEY_TO_HARDWARE"),src.index("doSoftwareKeyGen()"))
        self.assertIn("parsedParams.attestationChallenge == null",src)
        self.assertIn("!isAttestKeyRequest",src)
        self.assertIn("attestationKey == null",src)
        self.assertIn("!hasDeviceIdAttestation",src)
        self.assertEqual(src.count("doSoftwareKeyGen()"),1)

    def test_refuses_repeated_patch(self):
        patcher.patch(self.root)
        with self.assertRaisesRegex(RuntimeError,"anchor|already patched"):
            patcher.patch(self.root)

    def test_refuses_unrecognized_upstream_source(self):
        (self.root/patcher.REL).write_text("unexpected")
        with self.assertRaisesRegex(RuntimeError,"anchor"):
            patcher.patch(self.root)

class TestRepack(unittest.TestCase):
    def setUp(self):
        t=TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir=Path(t.name)
        self.baseline=self.dir/"baseline.zip"
        self.engine=self.dir/"new_engine.zip"
        self.output=self.dir/"candidate.zip"
        self.old_dex=b"old-pr76-dex"
        self.new_dex=b"new-dex-VINCE_PASS_NON_ATTESTED_KEY_TO_HARDWARE"
        self.payload={
            "tee_classes.dex":self.old_dex,
            "module.prop":b"id=tricky_store\nname=AlwaysStrong [Inject]\nversion=v1.0.5\nupdateJson=https://example.org/x\n",
            "engine.sh":b"ENGINE=inject\n",
            "service.sh":b"if as_on auto_keybox; then true; fi",
            "keybox_fetch.sh":b"keybox logic preserved",
            "attest.sh":b"TEE inject logic preserved",
            "zygisk/arm64-v8a.so":b"zygisk binary untouched",
            "lib/arm64-v8a/libTEESimulator.so":b"native unchanged",
        }
        self.makezip(self.baseline,self.payload)
        self.makezip(self.engine,{"classes.dex":self.new_dex})
        self.o_baseline=repacker.PR76_BASE_SHA256
        self.o_dex=repacker.PR76_DEX_SHA256
        repacker.PR76_BASE_SHA256=repacker.sha256(self.baseline)
        repacker.PR76_DEX_SHA256=hashlib.sha256(self.old_dex).hexdigest()
        self.addCleanup(lambda:setattr(repacker,"PR76_BASE_SHA256",self.o_baseline))
        self.addCleanup(lambda:setattr(repacker,"PR76_DEX_SHA256",self.o_dex))

    @staticmethod
    def makezip(path,payload):
        with ZipFile(path,"w") as out:
            for n,b in payload.items():out.writestr(n,b)

    def test_one_bytecode_file_changed_only(self):
        result=repacker.build(self.baseline,self.engine,self.output)
        self.assertEqual(result["changed_original_entries"],["tee_classes.dex"])
        with ZipFile(self.output) as out:
            self.assertEqual(out.read("tee_classes.dex"),self.new_dex)
            for n,data in self.payload.items():
                if n!="tee_classes.dex":self.assertEqual(out.read(n),data)
            self.assertEqual(len(out.namelist()),len(self.payload)+1)
            self.assertIsNone(out.testzip())

    def test_wrong_base_rejected(self):
        repacker.PR76_BASE_SHA256="0"*64
        with self.assertRaises(ValueError):repacker.build(self.baseline,self.engine,self.output)

    def test_inject_variant_required(self):
        self.payload["module.prop"]=self.payload["module.prop"].replace(b"AlwaysStrong [Inject]",b"AlwaysStrong")
        self.makezip(self.baseline,self.payload)
        repacker.PR76_BASE_SHA256=repacker.sha256(self.baseline)
        with self.assertRaises(ValueError):repacker.build(self.baseline,self.engine,self.output)

    def test_source_marker_required(self):
        self.makezip(self.engine,{"classes.dex":b"random other compiled engine"})
        with self.assertRaisesRegex(ValueError,"identifier"):
            repacker.build(self.baseline,self.engine,self.output)

    def test_no_inplace_overwrite(self):
        with self.assertRaises(ValueError):
            repacker.build(self.baseline,self.engine,self.baseline)

if __name__=="__main__":unittest.main()
