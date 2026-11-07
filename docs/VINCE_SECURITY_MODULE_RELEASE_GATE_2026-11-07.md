# Vince / SuperiorOS Android 13 — Release Gate & Module Findings

Date: 2026-11-07. **STATUS: RESEARCH ONLY, NOT READY TO FLASH AS A VERIFIED FINAL KERNEL.**

## Build configuration
- Device: Xiaomi Redmi 5 Plus (`vince`), MSM8953, arm64, legacy Linux 4.9.337.
- Root research backend: ReSukiSU pinned commit `24cc758fec61d44c45cafeea4c844fd0856f71c9`.
- SUSFS 2.3.0: pinned Linux 4.9 port commit `71345ded5af28f55d76ebcdc7a9df9cea56111e1`.
- NoMount built-in API v22: pinned commit `07efa370edb784327ee03877c9882ab2599a15ce`.
- Recovery installer: AnyKernel3, `do.devicecheck=1`, `device.name1=vince`.
- InstallerFIX3 validates an original Android boot dump before writing, checks SHA-256 readback, and attempts a verified rollback on readback mismatch. **None of this guarantees a bootable kernel.**

## Release checks (actual GitHub Actions)
- [Source SELinux gate](https://github.com/sahila7128-beep/vince-kernel-build/actions/runs/42327142901): FAIL AS DESIGNED. **Five source blockers remain**, including `ksu_file`, permissive root domain and broad SELinux allow.
- [Module ZIP scanner synthetic unit tests](https://github.com/sahila7128-beep/vince-kernel-build/actions/runs/42327995740): PASS. This runner does not have the user's actual module ZIPs.
- [AnyKernel installer safety file-based simulations](https://github.com/sahila7128-beep/vince-kernel-build/actions/runs/42328406189): PASS, **5/5**. No physical block device was used.
- [ReSukiSU build with installerFIX3](https://github.com/sahila7128-beep/vince-kernel-build/actions/runs/42327786014): inspect run conclusion before relying on its ZIP. Previous compile-success builds were still UNTESTED.

## User-supplied module ZIP audit (offline, read-only)
The nine ZIP files in the user's archive passed CRC, but this **does not** prove successful Android installation.

| Module | Observed / unresolved compatibility issue |
|---|---|
| BreZygisk v1.0.0 | Its `sepolicy.rule` allows `system_server system_server process execmem` **and** `zygote adb_data_file dir search`, matching two DirtySepolicy checks. |
| small_module v1.0.2 | Installer adds `type adbroot domain` and invokes `ksud sepolicy apply`; DirtySepolicy flags `adbroot`. |
| BreWheel v0.0.11 | Wildcard `allow * zygote unix_stream_socket` rule needs review; check ReZygisk version dependency. |
| fgetpriority v0.0.2 | No Linux 4.9 driver inside the provided module ZIP. |
| ReSuSFS + BRENE | Both control SUSFS; concurrent installation might conflict. ReSuSFS documents official support for KernelSU/BakaSU, not this ReSukiSU research backend. |
| NoMount v2.2.0 | Requires built-in API 22 on legacy Linux 4.9. Source configured; runtime driver not tested. |
| AlwaysStrong | Supplied file is labeled standard v1.0.5; the user's previously working **Inject variant** must not be silently replaced. |
| HMA-OSS | Archive passes structural checks; Zygisk and real Android runtime not tested. |

The module audit code **does not remove, edit, or install modules**.

## Device Tree compared against original SuperiorOS boot backup
- Original device-tree: **1591 nodes**, 8598 properties; research kernel: **1592 nodes**, 8603 properties.
- Original hardware node paths missing in research kernel: **0**.
- Existing property values changed: **39**, involving CPU clock/voltage bins and GPU frequency/bus configuration.
- Added GPU power-level node: **1**.
- Result: matching node coverage **does not mean equivalent performance/timing/stability**.

## What will NOT be claimed until a phone is tested
- OrangeFox/TWRP flashing succeeds
- SuperiorOS boot and touchscreen/Wi-Fi/fingerprint/charging functionality work
- SELinux stays enforcing, DirtySepolicy = 0 on-device
- All installed modules initialize without errors
- Any specific m-banking application accepts the device

Do not spoof test outcomes or claim application compatibility from a GitHub Actions compile. Keep a working original `boot.img` backup accessible outside recovery temporary storage.

## Relevant upstream references
- [Legacy SUSFS Linux 4.9 port](https://github.com/wxx9248/susfs4ksu) — documents that the Linux 4.9 patch omits `selinux_hide` for 5.10+.
- [NoMount driver](https://github.com/maxsteeel/nomount) — legacy drivers need kernel integration, and v2.2.0 requires API 22.
- [ReSuSFS module](https://github.com/ahmed-alnassif/ReSuSFS) — current support scope.
- [DirtySepolicy scanner](https://github.com/LSPosed/DirtySepolicy) — checks SELinux access and policy status, not just the enforcing flag.
