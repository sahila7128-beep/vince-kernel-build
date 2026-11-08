#!/usr/bin/env python3
"""Apply a strictly scoped RSA-OAEP/MGF1 default-digest correction.

Target: Enginex0/TEESimulator-RS v6.0.1-307.
No kernel files, certificate/keybox files, SELinux policy, or other modules
are changed. Fails closed if the upstream source layout is different.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: patch_engine.py <TEESimulator-RS checkout>")

root = Path(sys.argv[1]).resolve()
relative = Path("app/src/main/java/org/matrix/TEESimulator/interception/keystore/shim/SoftwareOperation.kt")
target = root / relative
if not target.is_file():
    raise SystemExit(f"ERROR: source file not found: {target}")

src = target.read_text(encoding="utf-8")
original = '''                val mgfDigest =
                    params.rsaOaepMgfDigest.firstOrNull()?.let {
                        JcaAlgorithmMapper.mapOaepDigest(it)
                    } ?: mainDigest'''
fixed = '''                // Android KeyMint RSA_OAEP_MGF_DIGEST defaults to SHA-1 when
                // the operation omits this parameter. Unlike generic JCA,
                // it must not inherit the RSA-OAEP message digest (SHA-256).
                val mgfDigest =
                    params.rsaOaepMgfDigest.firstOrNull()?.let {
                        JcaAlgorithmMapper.mapOaepDigest(it)
                    } ?: "SHA-1"'''
count = src.count(original)
if count != 1:
    raise SystemExit(
        f"ERROR: expected exactly one matching OAEP code block, found {count}. "
        "Upstream changed; refuse an unreviewed patch."
    )
patched = src.replace(original, fixed, 1)
assert patched.count('} ?: "SHA-1"') >= 1
assert original not in patched
target.write_text(patched, encoding="utf-8")
print(f"PATCHED: {relative}")
print("Invariant: omitted MGF1 digest => SHA-1; explicit MGF1 digest preserved.")
print("Not yet device-validated. Keep original RC3 and module backup.")
