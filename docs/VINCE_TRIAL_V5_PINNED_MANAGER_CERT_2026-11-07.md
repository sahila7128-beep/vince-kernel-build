# Vince TRIAL V5 — pinned legacy Manager certificate experiment

Date: 7 November 2026. This does **not** replace TRIAL V4's real boot evidence.
Build source change: commit 2b190971ac488367d02e0a4d498ab8bac5eda413.

## Exactly what changed

The build now appends EXPECTED_SIZE 744 and EXPECTED_HASH
b8eac4bd07e3cfee160808a6297cd59bae3878a66d233cfcaf383c3cc4e4395b
to the pinned ReSukiSU kernel/manager_sign.h.

This extends (does not replace) the static trusted Manager signature list. It is
intended for the **same source-commit Manager 34606 APK** built by the upstream
ReSukiSU CI at https://github.com/xixiaobei-bei/ReSukiSU/actions/runs/37106422885.

- Companion APK SHA256: 6709fc62a96d17e48bdb6bc8dc1ed1a541c32e60151963f0c968726e5699c690
- Certificate subject: C=US, O=Android, CN=Android Debug
- DER certificate size: 744 bytes
- SHA256 of DER certificate: b8eac4bd07e3cfee160808a6297cd59bae3878a66d233cfcaf383c3cc4e4395b
- Included APK library: arm64-v8a/libksud.so is a valid AArch64 Android ELF executable; binary SHA256 99f32c978b714ee735bf903759231a61700335c9432f4200aaa6d11cac0a6dcf.

Root/kernel ABI remains the pinned *legacy* GET_INFO ioctl and UAPI0.
There is NO UAPI4 emulation, NO change to privileged module SELinux rules,
NO change to SUSFS/NoMount kernel code, and NO hardware/device-tree edits.
This is a trial of a matching root+Manager version and certificate, not a
proof that UAPI4 or DirtySepolicy0 is implemented.

## Critical risks

1. The APK is signed with an Android DEBUG certificate, not the production
   ReSukiSU certificate. Pinned kernel will grant trusted-Manager status to
   apps signed with this specific key if they satisfy existing package checks.
   The key provenance and security posture are inferior to a trusted production
   release, and the same signing private key may not be available for updates.
   **NOT APPROPRIATE AS A PRODUCTION ROOT/BANKING SECURITY RELEASE.**
2. Installed Manager 35171 likely has a DIFFERENT certificate and higher version
   code. Android may refuse the old 34606 APK in-place. Uninstalling the old
   app can erase its app-specific data and risks losing management access.
   Do not uninstall anything until boot backup and original Manager APK are
   safely stored and the new kernel boots.
3. A legacy Manager may still show a warning if its version parser sees the
   kernel's honest source label "unknown-24cc758f" rather than a tagged semver.
   Do not spoof v4.0.0 or UAPI4 merely to hide a warning.
4. Nothing in this patch removes Root SELinux policy markers. DirtySepolicy
   still needs physical diagnosis; the no-spoof target is unresolved.
5. Android root, module installation and systemless module activation require
   physical device testing. Source/kernel compilation alone proves none.

## Conservative physical test order (only if CI build, hashes and ZIP pass)

- Keep an off-device boot.img backup (including working V4) and original
  authorized Manager 35171 APK; do not lock bootloader or format data.
- Flash **one** labelled V5 TRIAL kernel ZIP via the working custom recovery,
  verify boot and core hardware before changing Manager. Retain V4 rollback.
- If V5 boots, capture kernel version and current Manager screenshot. The
  original Manager 35171 will still show legacy-UAPI incompatibility.
- Only then, if willing to test the DEBUG-signed 34606 companion APK, ensure
  its SHA256 matches above. Because signatures/version codes differ, Android
  may require uninstalling the existing Manager; back up any app-specific data
  first and keep its reinstall APK. Never delete /data/adb.
- Confirm whether new Manager is authorized, root shell works, and the ksud
  version corresponds to 34606. Keep SELinux Enforcing. If Manager access is
  lost, restore the original authorized Manager APK; revert boot to V4 if needed.
- Next try only one harmless module first, verify install / reboot / mount /
  removal, and collect logs. The pinned ksud can run default installer without
  a metamodule, but systemless mount activation may need a metamodule.
- Do NOT activate small_module, BreZygisk's broad rules, or both SUSFS
  modules together until their conflicts and DirtySepolicy sources are audited.

Release status remains **TRIAL-ONLY** until actual phone results justify it.
