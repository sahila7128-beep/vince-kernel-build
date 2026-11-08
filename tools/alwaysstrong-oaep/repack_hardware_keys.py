#!/usr/bin/env python3
"""Build a *one-file delta* trial over the exact prior Vince PR76 module.

No root, keybox, Zygisk binary, module identity, native library, property,
or SELinux policy is changed. The sole original entry updated is TEE DEX;
a clear engineering notice is added. This is NOT proven phone compatible.
"""
from __future__ import annotations
from copy import copy
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import argparse
import hashlib

from repack_engine import safe_zip, require, parse_props, sha256

PR76_BASE_SHA256 = "5d1bd0ee2130674786752d9e2cf9fb9f01b3967f0a605b96adb670309a0befdb"
PR76_DEX_SHA256 = "453744e949d8bd9013a76916c2579004e73ec0eddf59cacd9a62f29ea9271d7c"
NOTICE = "VINCE_TEE_HARDWARE_KEY_PASSTHROUGH_TRIAL.txt"

def build(baseline: Path, candidate_engine: Path, output: Path) -> dict:
    if output.resolve() in (baseline.resolve(), candidate_engine.resolve()):
        raise ValueError("Must not overwrite original engine or module")
    require(sha256(baseline) == PR76_BASE_SHA256,
            "Refusing unknown baseline: requires previously CI-verified PR76 module")
    base_entries, base = safe_zip(baseline)
    engine_entries, engine = safe_zip(candidate_engine)
    try:
        props = parse_props(base.read("module.prop"))
        require(props.get("id") == "tricky_store", "Not AlwaysStrong")
        require(props.get("name") == "AlwaysStrong [Inject]", "Wrong variant")
        require(props.get("version") == "v1.0.5", "Wrong version")
        require("ENGINE=inject" in base.read("engine.sh").decode(), "Inject inactive")
        for required in ("tee_classes.dex", "service.sh", "keybox_fetch.sh", "attest.sh"):
            require(required in base_entries, "Missing " + required)
        require(b"as_on auto_keybox" in base.read("service.sh"), "Auto keybox changed")
        require("classes.dex" in engine_entries, "Engine missing classes.dex")
        require(NOTICE not in base_entries, "Already patched")
        require(hashlib.sha256(base.read("tee_classes.dex")).hexdigest() == PR76_DEX_SHA256,
                "Unexpected previous engine DEX")
        dex=engine.read("classes.dex")
        dexsha=hashlib.sha256(dex).hexdigest()
        require(dexsha != PR76_DEX_SHA256, "New candidate DEX identical to PR76 (no-op)")
        # The source change adds a unique string to confirm that this DEX
        # is the one built from the hardware passthrough patch.
        require(b"VINCE_PASS_NON_ATTESTED_KEY_TO_HARDWARE" in dex,
                "Expected source-patch identifier missing in DEX")
        output.parent.mkdir(parents=True,exist_ok=True)
        marker=(
            "VINCE ENGINEERING TEST: ORIGINAL HARDWARE KEY PASS-THROUGH\n"
            "Source patch: preserve actual hardware Keymaster for ALL non-attested key creation.\n"
            "Attestation-challenge requests retain upstream PR76 behavior.\n"
            "No hardware security level, device certification or application support is promised.\n"
            "All pre-existing entries except tee_classes.dex are byte-identical.\n"
            "EXPERIMENTAL; not tested on Redmi 5 Plus; retain original PR76 and official Inject backup.\n"
            "Previous module sha256: "+PR76_BASE_SHA256+"\n"
            "New DEX sha256: "+dexsha+"\n"
        ).encode()
        with ZipFile(output,"w") as dest:
            for item in base.infolist():
                dest.writestr(copy(item),dex if item.filename=="tee_classes.dex" else base.read(item))
            dest.writestr(NOTICE,marker,compress_type=ZIP_DEFLATED)
        dest_entries, check=safe_zip(output)
        try:
            require(set(dest_entries)==set(base_entries)|{NOTICE},"Output files added or lost")
            changed=[]
            for name in base_entries:
                if check.read(name) != base.read(name):
                    changed.append(name)
            require(changed==["tee_classes.dex"],f"Changed entries outside DEX: {changed}")
            require(check.read("tee_classes.dex")==dex,"DEX mismatch")
        finally:
            check.close()
        return {"baseline_sha256":PR76_BASE_SHA256,"candidate_dex_sha256":dexsha,
                "module_sha256":sha256(output),"changed_original_entries":["tee_classes.dex"]}
    finally:
        base.close()
        engine.close()

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline",type=Path,required=True)
    p.add_argument("--engine",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    print(build(args.baseline,args.engine,args.output))
