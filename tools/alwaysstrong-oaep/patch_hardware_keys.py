#!/usr/bin/env python3
"""Surgical Android Keystore compatibility patch for TEESimulator-RS v308.

Root cause guarded: target.txt AUTO mode can resolve to GENERATE if hardware
attestation of an EC key fails. In that case the stock interceptor forges even
NON-ATTESTATION keys (AES/HMAC/RSA/EC) used to protect ordinary app data,
instead of using the real Keymaster. This breaks compatibility/persistence.

New policy: ALWAYS pass non-attestation generateKey calls through to actual
Keystore/Keymaster. Interception of requests involving attestation challenge,
attest key, or device IDs is unchanged. Explicit/forced GENERATE modes also
cannot steal ordinary non-attested cryptographic keys.

Not an integrity-bypass fix; cannot make the hardware secure boot authentic.
"""
from pathlib import Path
import argparse
import hashlib

REL = Path("app/src/main/java/org/matrix/TEESimulator/interception/keystore/shim/KeyMintSecurityLevelInterceptor.kt")
ANCHOR = '''                SystemLogger.trace {
                    "[TRACE-$txId] generateKey alias=${keyDescriptor.alias} algo=${parsedParams.algorithm} challenge=${parsedParams.attestationChallenge?.size ?: "null"} serial=${parsedParams.serial != null} imei=${parsedParams.imei != null} noAuth=${parsedParams.noAuthRequired} purposes=${parsedParams.purpose}"
                }'''

PATCH = '''                // VINCE_KEYSTORE_HARDWARE_KEYS: Non-attested crypto MUST stay in the
                // actual Keymaster, regardless of AUTO/GENERATE target configuration.
                // AUTO can fall back to GENERATE when only attestation provisioning
                // is unavailable. That does NOT imply AES/HMAC or ordinary RSA/EC
                // keys should be software-generated, with different persistence,
                // error codes, user-auth handling, and hardware key isolation.
                // Attestation requests continue through their existing dispatch.
                if (
                    parsedParams.attestationChallenge == null &&
                        !isAttestKeyRequest &&
                        attestationKey == null &&
                        !hasDeviceIdAttestation
                ) {
                    // The same alias may previously have been software-generated.
                    // Evict its synthetic/patch cache before issuing a new
                    // hardware generateKey or getKeyEntry would return stale
                    // software key metadata despite the real HAL replacement.
                    cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))
                    logProbe("VINCE_PASS_NON_ATTESTED_KEY_TO_HARDWARE")
                    return TransactionResult.ContinueAndSkipPost
                }

''' + ANCHOR

def patch(base: Path) -> str:
    p = base / REL
    src = p.read_text(encoding="utf-8")
    if src.count(ANCHOR) != 1:
        raise RuntimeError(f"Expected EXACTLY one dispatch anchor in {p}; got {src.count(ANCHOR)}. Refusing silent patch.")
    if "VINCE_KEYSTORE_HARDWARE_KEYS" in src:
        raise RuntimeError("Source already patched.")
    # Require original high-risk path to exist to avoid patching wrong engine.
    required = (
        "ConfigurationManager.shouldGenerate(callingUid)",
        "DeviceAttestationService.isTeeFunctional",
    )
    # AUTO -> GENERATE policy lives in a separate config file; validate both files.
    if required[0] not in src:
        raise RuntimeError("Expected original software-key generation dispatch not found.")
    cfg = (base / "app/src/main/java/org/matrix/TEESimulator/config/ConfigurationManager.kt").read_text()
    if required[1] not in cfg or "else Mode.GENERATE" not in cfg:
        raise RuntimeError("Expected AUTO fallback behavior missing; review upstream first.")
    dst = src.replace(ANCHOR, PATCH)
    assert dst.count("VINCE_PASS_NON_ATTESTED_KEY_TO_HARDWARE") == 1
    assert dst.count(ANCHOR) == 1
    assert dst.count("doSoftwareKeyGen(") == src.count("doSoftwareKeyGen(")
    assert dst.count("AttestationPatcher.patchCertificateChain(") == src.count("AttestationPatcher.patchCertificateChain(")
    p.write_text(dst, encoding="utf-8")
    return hashlib.sha256(p.read_bytes()).hexdigest()

if __name__ == "__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("repo",type=Path)
    args=ap.parse_args()
    print("patched-source-sha256:",patch(args.repo))
