#!/usr/bin/env python3
"""Vince TEE v308: *ONLY* replace the AlwaysStrong TEESimulator-RS bytecode.

Source of replacement: adamaru/TEESimulator-RS v6.0.1-308, PR #76.
No patch to original native libraries, Zygisk Inject binary, keybox, module
installer, shell scripts, module.prop or root/kernel/ROM. Offline ZIP-only work.
STRICTLY A TEST BUILD. Hardware integrity and app compatibility are unverified.
"""
from __future__ import annotations
import argparse
from copy import copy
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

from repack_engine import safe_zip, require, parse_props, sha256

EXPECTED_PR76_DEX = "453744e949d8bd9013a76916c2579004e73ec0eddf59cacd9a62f29ea9271d7c"


def repack(original: Path, v308_engine: Path, output: Path) -> dict:
    require(original.resolve() != v308_engine.resolve(), "Source paths overlap")
    require(output.resolve() not in (original.resolve(), v308_engine.resolve()),
            "Output must not overwrite original ZIP files")
    o_entries, orig = safe_zip(original)
    e_entries, engine = safe_zip(v308_engine)
    try:
        require("module.prop" in o_entries, "Original module.prop is missing")
        props = parse_props(orig.read("module.prop"))
        require(props.get("id") == "tricky_store", "Not AlwaysStrong")
        require(props.get("name") == "AlwaysStrong [Inject]",
                "Must be AlwaysStrong [Inject], not standard/Lite")
        require(props.get("version") == "v1.0.5", "Expected exact v1.0.5")
        require("engine.sh" in o_entries and b"ENGINE=inject" in orig.read("engine.sh"),
                "Inject engine variant is not enabled")
        for essential in ("tee_classes.dex", "keybox_fetch.sh", "service.sh", "attest.sh"):
            require(essential in o_entries, f"Original module missing {essential}")
        require(b"auto_keybox" in orig.read("service.sh"),
                "Automatic keybox check missing: fail rather than regress")
        require("classes.dex" in e_entries, "v308 engine missing classes.dex")
        dex = engine.read("classes.dex")
        import hashlib
        digest = hashlib.sha256(dex).hexdigest()
        require(digest == EXPECTED_PR76_DEX,
                f"Wrong v308 bytecode SHA256: {digest}")
        require(orig.read("tee_classes.dex") != dex,
                "Source already has the replacement bytecode; refuse no-op")
        require("VINCE_TEE_V308_TRIAL.txt" not in o_entries,
                "Already marked as trial; original ZIP required")
        marker = (
            "VINCE TEE v308 DEX-ONLY TRIAL (NOT DEVICE VALIDATED)\n"
            "PR #76: https://github.com/Enginex0/TEESimulator-RS/pull/76\n"
            "Original SHA256: " + sha256(original) + "\n"
            "Replacement engine SHA256: " + sha256(v308_engine) + "\n"
            "v308 classes.dex SHA256: " + digest + "\n"
            "Kernel is NOT included. Verify app launches + Play Integrity on-device.\n"
            "Keep the original official v1.0.5 Inject ZIP for recovery.\n"
            "module.prop/updateJson, scripts and native libraries remain unmodified.\n"
        ).encode("utf-8")
        output.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(output, "w") as z:
            for member in orig.infolist():
                content = dex if member.filename == "tee_classes.dex" else orig.read(member)
                z.writestr(copy(member), content)
            z.writestr("VINCE_TEE_V308_TRIAL.txt", marker, compress_type=ZIP_DEFLATED)
        entries, check = safe_zip(output)
        try:
            require(set(entries) == set(o_entries) | {"VINCE_TEE_V308_TRIAL.txt"},
                    "Output ZIP changed file list")
            for name in o_entries:
                if name == "tee_classes.dex":
                    require(check.read(name) == dex, "Incorrect v308 dex")
                else:
                    require(check.read(name) == orig.read(name),
                            f"Unexpected mutation of {name}; reject artifact")
            require(check.read("module.prop") == orig.read("module.prop"),
                    "module.prop must remain identical to original")
            require("boot.img" not in entries and "Image" not in entries,
                    "Kernel payload forbidden")
        finally:
            check.close()
        return {"original_sha256": sha256(original),
                "v308_dex_sha256": digest,
                "output_sha256": sha256(output),
                "changed_original_file": "tee_classes.dex",
                "original_version": props["version"]}
    finally:
        orig.close()
        engine.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--v308", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for k, v in repack(args.original, args.v308, args.output).items():
        print(f"{k}: {v}")
