# Vince TRIAL V4 — real-device screenshots and confirmed ReSukiSU UAPI mismatch

Date: 2026-11-07 (user supplied screenshots, not a physical test performed by GitHub Actions).

## Physical-device observation
- Xiaomi Redmi 5 Plus (`vince`), SuperiorOS Android 13, kernel reports `4.9.337-Yoru`.
- Android boot succeeded; ReSukiSU Manager v4.2.0-rc3 (35171/4) shows `Berfungsi` and `Built-in`.
- Driver reports `unknown-24cc758f@ReSukiSU (34606/0)`. The source pin `24cc758f` matches our compiled kernel.
- Manager displays a red `Kernel update required` banner; counters are `SuperUser: 0, Modul: 0`.
- DirtySepolicy 2.2 reports `WARNING: found adb_root; found KernelSU;`.
- This is evidence of first boot, not proof that module management, SUSFS and banking compatibility work.

## Root cause of red manager warning
Source of pinned root: `https://github.com/xixiaobei-bei/ReSukiSU/blob/24cc758fec61d44c45cafeea4c844fd0856f71c9/kernel/supercalls.h`
- `KSU_IOCTL_GET_INFO _IOC(_IOC_READ, 'K', 2, 0)` uses a zero-sized **legacy** ioctl.
Manager source for the installed 35171 APK: `https://github.com/Baka-SU/BakaSU/blob/v4.2.0-rc3/manager/app/src/main/cpp/ksu.c`
- Manager first tries a **size-encoded** `KSU_IOCTL_GET_INFO`; when that fails it falls back to `KSU_IOCTL_GET_INFO_LEGACY` and explicitly sets `g_version.uapi_version = 0`.
- New Manager `KERNEL_SU_UAPI_VERSION = 4`: `https://github.com/Baka-SU/BakaSU/blob/v4.2.0-rc3/uapi/supercall.h`
- Manager `Natives.isFullFeatured()` requires `isManager && kernelUAPIVersion == managerUAPIVersion`: `https://github.com/Baka-SU/BakaSU/blob/v4.2.0-rc3/manager/app/src/main/java/com/resukisu/resukisu/Natives.kt`.
- Thus `34606/0` versus `35171/4` directly explains `Kernel update required`, even while `Built-in` is shown.

**Do not simply advertise UAPI=4 in an old kernel**: unsupported commands and semantics could break app profiles/modules/security. Either find and validate a truly matching manager/ksud for the legacy root ABI or correctly port all required UAPI commands and verify with on-device tests.

## DirtySepolicy warnings
- `found KernelSU` is consistent with pinned root source creating `ksu_file`. This is an actual SELinux marker.
- `found adb_root` indicates an `adbroot` context exists. Its source cannot be uniquely determined from screenshots; a previous module, custom ROM policy, or other modification may contribute.
- The displayed `0 modules` is **not** proof no modules exist on disk, because the Manager currently has an ABI compatibility warning.
- Do not edit the live SELinux policy or remove `/data/adb` without a verified diagnosis and backup.

## Next safe stage
1. Keep external backup of current working Boot; do **not** update kernel from the Manager's red banner or lock bootloader.
2. Resolve kernel/Manager UAPI compatibility on the build branch; actual command support, not version-number spoofing.
3. Validate `ksud` pairing, module management and SUSFS/NoMount version commands **on the device**.
4. Establish origin of `adbroot` policy using read-only diagnostics before any removal. DirtySepolicy 0 and acceptance by individual banking apps remain unverified.

Status: **BOOT OBSERVED ON DEVICE; MANAGER API NOT FULLY COMPATIBLE; DIRTYSEPOLICY FAIL; NOT RELEASE READY**.
