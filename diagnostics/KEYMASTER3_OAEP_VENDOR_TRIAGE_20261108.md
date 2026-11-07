# Vince Keymaster 3.0 OAEP interoperability (2026-11-08)

STATUS: Device-specific evidence. NOT a flashable fix. Keep current C12-SECURETEST kernel.

## Observed on Redmi 5 Plus, SuperiorOS Android 13
- Vendor Keymaster 3.0 service running; AndroidKeyStore test keys hardware-backed.
- SHA256 OAEP / MGF1 SHA1: hardware decrypt fails even with independent RFC8017 ciphertext. Code -38 / OAEP_DECODING_ERROR.
- SHA256 OAEP / MGF1 SHA256: independently encoded RFC8017 ciphertext decrypts in implicit hardware default path (v4 P and R).
- SHA1 OAEP / MGF1 SHA1: hardware decrypt works.
- Software implementations support both variants.
- API-reported MGF1 digest differs from effective observed hardware behavior.

## Implications
Legacy Android Keymaster requires OAEP MGF1 SHA1, independently of the main SHA digest. A genuine global repair requires a verified vendor/TEE Keymaster implementation honoring the contract and tests for existing hardware-bound keys. The working combined C12-SECURETEST recovery ZIP has BOOT and SELinux policy assets but contains NO Keymaster/TrustZone service or firmware. Kernel-only rebuild cannot establish a TEE fix.

A narrowly scoped app workaround for NEW messages uses RSA OAEP SHA256/MGF1 SHA256 software public-key encryption and implicit AndroidKeyStore default-mode private-key decryption, after an ephemeral hardware key self-test. This cannot repair existing ciphertext or other apps, and is NOT a system-wide security fix.

Other Duck Detector observations: intermittent SELinux timing has no stock baseline; intermittent WebView shared-dirty memory is not a proven kernel defect. Custom ROM and root-related warnings describe installed features. DirtySepolicy reported 0 and SELinux Enforcing in last device evidence.

## Sources
https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal
https://developer.android.com/privacy-and-security/cryptography
https://github.com/eltavine/Duck-Detector-Refactoring
