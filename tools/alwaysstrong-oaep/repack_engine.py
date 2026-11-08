#!/usr/bin/env python3
"""Repack a USER-SUPPLIED official AlwaysStrong [Inject] v1.0.5 ZIP with the
corrected TEESimulator-RS engine. Never flashes or modifies the handset.

IMPORTANT: A compiled engine from a different upstream release is not guaranteed
to be binary-compatible. This is a trial only, requiring on-device validation.
The existing official ZIP must be kept as a rollback.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for block in iter(lambda: f.read(2**20), b""):
            h.update(block)
    return h.hexdigest()


def require(cond: bool, message: str) -> None:
    if not cond:
        raise ValueError(message)


def safe_zip(p: Path) -> tuple[dict[str, ZipInfo], ZipFile]:
    require(p.is_file(), f"Missing ZIP: {p}")
    z = ZipFile(p)
    bad = z.testzip()
    require(bad is None, f"ZIP integrity failed at {bad}: {p}")
    entries: dict[str, ZipInfo] = {}
    total = 0
    for entry in z.infolist():
        name = entry.filename
        path = PurePosixPath(name)
        require(
            not name.startswith("/") and "\\" not in name
            and not any(x in ("", ".", "..") for x in name.strip("/").split("/"))
            and name not in entries and name != "",
            f"Unsafe or duplicate ZIP entry: {name!r}",
        )
        unix_mode = (entry.external_attr >> 16) & 0xFFFF
        require(not stat.S_ISLNK(unix_mode), f"ZIP symlink forbidden: {name}")
        require(not (entry.flag_bits & 1), f"Encrypted ZIP entry forbidden: {name}")
        total += entry.file_size
        require(total <= 125 * 2**20, "Uncompressed ZIP payload over 125 MiB")
        entries[name] = entry
    return entries, z


def parse_props(data: bytes) -> dict[str, str]:
    result = {}
    for line in data.decode("utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, val = line.split("=", 1)
            result[key.strip()] = val.strip()
    return result


def version_trial(prop: bytes) -> bytes:
    text = prop.decode("utf-8")
    lines = []
    for line in text.splitlines():
        if line.startswith("version="):
            line = "version=v1.0.5 (vince-oaep-sha1-TRIAL)"
        elif line.startswith("name="):
            line = "name=AlwaysStrong [Inject] (Vince OAEP TRIAL)"
        elif line.startswith("updateJson="):
            # Avoid the official update silently replacing this unvalidated build.
            continue
        lines.append(line)
    return ("\n".join(lines) + "\n").encode("utf-8")


def repack(original: Path, engine: Path, output: Path) -> dict:
    require(output.resolve() not in (original.resolve(), engine.resolve()),
            "Output path must differ from both input files")
    orig_entries, orig = safe_zip(original)
    eng_entries, eng = safe_zip(engine)
    try:
        require("module.prop" in orig_entries, "Not a root module ZIP (no module.prop)")
        props = parse_props(orig.read("module.prop"))
        require(props.get("id") == "tricky_store", "Wrong original module ID")
        require(props.get("name") == "AlwaysStrong [Inject]",
                "Must use the ORIGINAL AlwaysStrong [Inject] ZIP, not default/Fork/NoPIF")
        require(props.get("version") == "v1.0.5",
                "Expected official AlwaysStrong [Inject] v1.0.5")
        require("engine.sh" in orig_entries and re.search(rb"(?m)^ENGINE=inject\s*$",
                orig.read("engine.sh")), "Not the inject-s engine configuration")
        require("attest.sh" in orig_entries and "tee_classes.dex" in orig_entries,
                "TEESimulator-RS layout is missing in the original module")
        require("classes.dex" in eng_entries,
                "Patched TEESimulator-RS ZIP must contain classes.dex")
        replacements = {"tee_classes.dex": eng.read("classes.dex")}
        for name, obj in eng_entries.items():
            if name.startswith("lib/") and name.endswith(".so") and not obj.is_dir():
                require(name in orig_entries,
                        f"Original AlwaysStrong lacks expected engine library {name}")
                replacements[name] = eng.read(name)
        require(any(n.startswith("lib/arm64-v8a/") for n in replacements),
                "Patched engine has no arm64-v8a native library")
        require("zygisk/" not in replacements,
                "Never replace PlayIntegrityFix/zygisk payload")
        require("module.prop" not in replacements,
                "Never accept module.props from engine module")
        replacements["module.prop"] = version_trial(orig.read("module.prop"))
        require(parse_props(replacements["module.prop"])["id"] == "tricky_store",
                "Module identity was accidentally changed")
        marker = (
            "VINCE AL-FinaSU RC3 / AlwaysStrong Inject v1.0.5 OAEP SHA-1 TRIAL\n"
            "Not an attestation trust or SELinux fix. Not device-tested.\n"
            "This ZIP only swaps TEESimulator-RS classes.dex + matching native libs.\n"
            "Original official ZIP SHA256: " + sha256(original) + "\n"
            "Patched TEESimulator-RS ZIP SHA256: " + sha256(engine) + "\n"
            "Keep original v1.0.5 Inject ZIP for rollback. Do not flash a kernel.\n"
            "Kernel baseline Vince-C12-RC3.zip is NOT included.\n"
        ).encode("utf-8")
        require("VINCE_OAEP_TRIAL_README.txt" not in orig_entries,
                "Input ZIP already appears to be a trial; use unmodified official ZIP")
        output.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(output, "w") as out:
            for item in orig.infolist():
                data = replacements.get(item.filename)
                if data is None:
                    data = orig.read(item)
                # ZipInfo from original preserves permissions/relative paths.
                out.writestr(item, data)
            out.writestr("VINCE_OAEP_TRIAL_README.txt", marker, compress_type=ZIP_DEFLATED)
        final_entries, result = safe_zip(output)
        try:
            require(set(final_entries) == set(orig_entries) | {"VINCE_OAEP_TRIAL_README.txt"},
                    "Unexpected output entry names")
            for name in orig_entries:
                if name not in replacements:
                    require(orig.read(name) == result.read(name),
                            f"Unintended binary modification at {name}")
            for name, expected in replacements.items():
                require(result.read(name) == expected,
                        f"Replacement mismatch at {name}")
            require(result.read("keybox.xml") == orig.read("keybox.xml")
                    if "keybox.xml" in orig_entries else True,
                    "Keybox.xml was unexpectedly modified")
            require(not any(x in final_entries for x in ("boot.img", "Image", "dtb")),
                    "Boot/kernel payload forbidden")
        finally:
            result.close()
        return {
            "original_sha256": sha256(original),
            "engine_sha256": sha256(engine),
            "output_sha256": sha256(output),
            "replaced_entries": sorted(replacements),
            "output_file": str(output),
        }
    finally:
        orig.close()
        eng.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--original", required=True, type=Path,
                    help="User-supplied unmodified AlwaysStrong-v1.0.5-inject.zip")
    ap.add_argument("--engine", required=True, type=Path,
                    help="Patched TEESimulator-RS release ZIP from GitHub Actions")
    ap.add_argument("--output", required=True, type=Path,
                    help="Output trial ZIP, never the original")
    opts = ap.parse_args()
    info = repack(opts.original, opts.engine, opts.output)
    for field, value in info.items():
        print(f"{field}: {value}")
