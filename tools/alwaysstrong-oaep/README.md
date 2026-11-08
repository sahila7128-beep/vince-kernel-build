# Vince / AlwaysStrong [Inject] v1.0.5 — RSA-OAEP MGF1 default correction (trial)

**Status:** engineering trial, NOT a verified device fix or release kernel. **Base kernel remains Vince-C12-RC3.zip unchanged**.

## Source-confirmed defect

Enginex0/TEESimulator-RS tag `v6.0.1-307`, file:
`app/src/main/java/org/matrix/TEESimulator/interception/keystore/shim/SoftwareOperation.kt`

At `CipherPrimitive` when RSA-OAEP digest is SHA-256 and no MGF1 digest is supplied in the Keystore operation, the simulator chooses `mainDigest`, i.e. SHA-256, as its MGF1 digest. Android KeyMint's default MGF1 digest is SHA-1. If the Android framework passes no MGF1 tag while the encryptor uses explicit `OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, ...)`, the private-key decrypt uses the wrong MGF1 digest and fails in `finish()`. This exactly matches an **identified, plausible** mechanism for the user's Duck Detector `roundTrip=false, decryptedBytes=0` when AlwaysStrong is enabled.

User's controlled A/B test on 2026-11-08:
- With AlwaysStrong [Inject] on: TEE attestation injected, but RSA-OAEP SHA256 roundtrip fails in Duck.
- With AlwaysStrong off: independent Vince KeyMint Diagnostic V4 RSA-OAEP SHA256/MGF1 SHA1 passes through the real Android Keystore. Duck then shows the stock software-attestation/revoked-chain issue instead.
- SELinux is Enforcing and DirtySepolicy checks pass; Duck's ~52 ns timing heuristic remains separately red.

## Scope / safeguards

- This patch changes only the MGF1 **omitted-parameter fallback** in TEESimulator-RS's `CipherPrimitive`. Explicitly requested MGF1 digests are unchanged.
- No keybox, private cert, device key, bootloader status, kernel, device-tree, vendor firmware, partition, system property, or SELinux rules are altered.
- Failing Duck timing is NOT evidence of missing SELinux enforcement; do not insert deliberate delays or weaken the kernel.
- Synthetic attestation is NOT hardware-backed secure boot, and a revoked real attestation certificate cannot be repaired by a module.
- The patch is intentionally **not declared successful** until the built package passes Android boot, module reload and repeated crypto regression checks on Vince. The original AlwaysStrong ZIP and boot recovery backup must be retained.

## CI builder

Workflow `.github/workflows/alwaysstrong-oaep-vince.yml` clones pinned TEESimulator-RS `v6.0.1-307`, patches source with an exact-match guard, builds its release module via Android/Gradle, builds official AlwaysStrong `v1.0.5` **inject** variant with the patched TEE engine, and exports a **TRIAL** artifact. If tag, code structure or compilation differs, CI stops rather than shipping a deceptive package.

Manual reproduction (if tooling available):

```bash
git clone --depth 1 -b v6.0.1-307 https://github.com/Enginex0/TEESimulator-RS.git tee-src
python3 tools/alwaysstrong-oaep/patch_engine.py tee-src
(cd tee-src && ./gradlew zipRelease)
git clone --depth 1 -b v1.0.5 https://github.com/evoker0/AlwaysStrong.git alwaysstrong
(cd alwaysstrong && bash build.sh --variant inject --tee-file ../tee-src/out/TEESimulator-RS-*-Release.zip)
```

## Test gate on the real handset

1. Do not flash/replace the **kernel**. Make a backup and record modules + ROM state.
2. Install the *trial module only* via FinaSU Manager, reboot; do NOT install the standalone TEE engine on top of AlwaysStrong.
3. Run Vince KeyMint Diagnostic V4 to compare RSA-OAEP SHA256/MGF1 SHA1, SHA1/MGF1 SHA1 controls; run Duck complete report.
4. Validate that `roundTrip=true, decryptedBytes=29` on the same decrypt path as the prior failing test, and that other crypto and module functions remain good.
5. If regressions occur, reinstall the original official `AlwaysStrong-v1.0.5-inject.zip` and reboot.

Upstream provenance:
- https://github.com/Enginex0/TEESimulator-RS/tree/v6.0.1-307
- https://github.com/evoker0/AlwaysStrong
- https://developer.android.com/privacy-and-security/cryptography#oaep-mgf1-message-digest

This trial does **not** address Duck's bootloader/TEE attest-chain anomalies with the interceptor disabled, nor its experimental SELinux timing Danger.
