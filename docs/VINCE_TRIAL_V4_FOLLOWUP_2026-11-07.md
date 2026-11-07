# Vince TRIAL V4 follow-up — 7 November 2026

Baseline PRESERVED: ZeroTwo Linux 4.9.337, pinned ReSukiSU 24cc758fec61d44c45cafeea4c844fd0856f71c9, SUSFS v2.3.0, NoMount API 22 and AnyKernel installer FIX4.

## Findings and actual tests

- The phone booted TRIAL V4 (user screenshot). ReSukiSU Manager 35171/UAPI4 showed kernel driver 34606/UAPI0, with warning "Kernel update required". Module installation has not been proven.
- Kernel GitHub Actions build 42329257559 SUCCESS. Installer sandbox 42329376164 passed 7/7 synthetic scenarios; no physical OrangeFox was used.
- Re-downloaded the original build artifact: one flash ZIP SHA256 is 0a3874e5e1f962647a9e2548436a89c99f226a72bd674cc0cf01dcefd73db822, equal to GitHub manifest; CRC check PASS.
- Pinned ReSukiSU source contains old zero-sized GET_INFO ioctl; the same-commit Manager uses this old API. The BakaSU Manager v4.2.0-rc3 (35171) uses size-encoded ioctl, falls back to legacy and sets UAPI0. Merely advertising UAPI4 would not implement the new commands.
- Found pinned-source upstream ReSukiSU successful Manager CI run 37106422885 (3 October 2026), with Manager-release and ksud artifacts. The Manager-release APK certificate was measured: DER size 744, SHA256 b8eac4bd07e3cfee160808a6297cd59bae3878a66d233cfcaf383c3cc4e4395b. It DOES NOT match the trust-list keys in pinned kernel/manager_sign.h. Do not install this APK as an assumed working replacement.
- DirtySepolicy observed adb_root and KernelSU. The pinned root policy still creates ksu_file and permissive/broad rules; a user module small_module also contains adbroot creation. The on-device origin of adb_root is not yet established.

## Safe tools and next gate

- scripts/audit-vince-manager-apk.py statically compares APK v2/v3 signer certificates against pinned manager_sign.h (NOT Android full signature verification or runtime root test). Nonmatch exit code 2 is a blocker.
- scripts/vince-diagnose-readonly.sh collects kernel, SELinux, daemon version, existing module IDs and suspicious policy lines through Android adb shell; it DOES NOT modify the device.
- Keep working boot backup outside the phone. Do not uninstall the authorized Manager, spoof UAPI4, edit SELinux live, delete /data/adb, or install incompatible module variants.
- Proper remedy: use a signed and trusted legacy-ABI Manager/ksud pair OR fully backport modern UAPI4 semantics and test. Root/profile/sepolicy/daemon compatibility and hardware must be checked physically.
- A NEW kernel ZIP is not warranted until a valid root ABI or targeted policy implementation actually changes kernel code; do not rebrand an unchanged TRIAL V4 as V5.

STATUS: BOOT OBSERVED; UAPI MISMATCH; UPSTREAM MATCHED APK NOT TRUSTED; DIRTYSEPOLICY NOT ZERO; NEW FLASH NOT RECOMMENDED.
