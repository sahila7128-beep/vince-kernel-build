# VINCE C12-RC3 — Root exposure and banking security audit
*9 Nov 2026; based on six Duck reports 09:22–09:26 GMT+7, Native Detector 7.6.1 screenshots, and previously inspected module sources.*

## Scope / limitations

User's objective: use m-banking safely without account issues. User reports
the banking applications open and no longer force-close; login has NOT been
attempted because of detection concerns. The user previously reported a Shopee
order canceled due to device/security risk; there is no evidence of the precise
risk model or any m-banking-specific detection yet.

A device rooted with FinaSU, unlocked/modified boot chain, custom SuperiorOS
Android 13 and runtime interception **cannot be certified as an unmodified,
trusted device by a local audit**. Passing a spoofed/instrumented Play Integrity
check does not change the physical bootloader, hardware roots of trust, or any
financial institution's own risk logic. No step here bypasses bank anti-tamper
checks. No bank login should be recommended based only on green detector UI.

## Direct evidence, versus inference

| Surface | Direct observation | Scope |
|---|---|---|
| Android Keystore/TEE | Six scans show TEE CLEAR, RSA-OAEP SHA256 OK; MGF1 explicit skipped | **Previously failing operation repaired** with PR76 DEX-only; NOT proof of every crypto and financial use case |
| SELinux | Enforcing, strong, no permissive domains, DirtySepolicy original checks clean | Intermittent Duck DANGER is experimental ~52 ns app_zygote timing, not a proven policy compromise |
| Root manager identity | Duck recognizes `me.yuki.fina`, from native payload `libksud.so` | Installed manager application visibly present to Duck; not evidence Duck has root |
| Package/modification footprint | Duck identifies HMA-OSS package `org.frknkrc44.hma_oss` by PackageManager, APK context and open FD | If unused, an extra unneeded modification tool can be removed |
| Property residue | `persist.sys.pixelprops.gms` present, value `0`; Native Detector notes `persist.sys.pixelprops.gphotos` and `config_certifiedKeybox` | Switching UI GMS spoof OFF does not necessarily remove key existence. Do not blindly edit system property area or alter attestation |
| Modified ROM | Duck recognizes LineageOS/Omni signatures; Native Detector shows abnormal boot state | Genuine custom ROM traces exist; cannot be resolved by simply changing a root module |
| Mount view | Duck Mount card INFO, restricted visibility, no confirmed suspicious mount in its own process | Native Detector independently reports suspicious mount but current screenshots lack the expanded mount path, so *cannot* attribute to specific module |
| Memory | One of six scans flagged transient 4KB shared-dirty WebView code page; other scans didn't | No confirmed native hook; avoid treating as proof of exploitation |

## Source-examined optional component

The separate upstream `backslashxx/small_module` release 102 contains
only module.prop and customize.sh; it declares a `adbroot` SELinux domain
and adds `allow fsck_untrusted fsck_untrusted capability sys_admin` and,
on volume-up during install, `allow shell su process transition`.
That matches the allowed `fsck_untrusted` edge in Duck, **but cannot prove
this module alone caused the edge** (ROM rules may also). This module neither
repairs TEE nor restores a non-root boot chain. For a device not using
root ADB workflows, turning it OFF via FinaSU Manager is a reversible
security hardening candidate. DO NOT flip SELinux to permissive or add
a compensating allow rule.

Source: https://github.com/backslashxx/small_module/blob/102/module/customize.sh

## Priority actions (non-evasive; preserve PR76 and current boot image)

1. **Keep the known-good C12-RC3, PR76 DEX-only and custom keybox unchanged.**
   Preserve private backups. Do not flash or "upgrade" injection layers for
   banking account acceptance; never share keybox XML or its private keys.
2. Inventory all **eight module IDs** before changing anything. A read-only
   helper lives at `tools/root-exposure/vince-security-audit.sh`. Its sole
   purpose is collecting module IDs, active/disabled state and narrowly chosen
   system indicators. Review its source before granting superuser permissions.
   It never sends data over the network, never alters properties/SELinux or
   touches the user's private keybox.
3. If `small_module` is active and there is no demonstrable requirement for
   adbroot, **disable it temporarily** through FinaSU Manager and reboot.
   Check SELinux remains enforcing, module functions remain intact, and
   that kernel/TEE still pass; if vital access breaks, restore the module.
4. **Review whether HMA-OSS and optional spoofing components are genuinely
   needed for legitimate device workflows.** Unneeded modules/manager apps
   expand the attack surface. Uninstalling an unnecessary app is not
   equivalent to guaranteeing a banking app accepts the device; do not chase
   detectors with concealment or property-falsification hooks.
5. If a bank requires **authentic unmodified boot/TEE**, its supported
   path is an unrooted, bank-supported device with genuine verified boot.
   Removing FinaSU entirely from Vince would disrupt its rooted module
   setup and might still leave modified boot and custom-ROM indicators.
   Restoring fully verified boot may require official, device-specific
   firmware; **never relock the bootloader while running a custom ROM**.
6. Ask the bank through official support whether the current rooted/
   custom-ROM device is supported for login. No test detector can guarantee
   no security review or account block. This is especially important for
   transaction authorization.
7. For an app that **actually crashes**, a targeted AndroidRuntime/Keystore
   stack trace can show whether a system defect remains; for policy-based
   denials, do not force app integrity bypass.

## Running the private read-only inventory on a PC

Download and inspect:
https://github.com/sahila7128-beep/vince-kernel-build/blob/audit/vince-root-exposure-20261109/tools/root-exposure/vince-security-audit.sh

With ADB already installed and trusted USB debugging, copy the helper to
`/data/local/tmp/vince-security-audit.sh`. Run using an authorized `su`
shell outside any banking application. Capture its standard output as
`vince-root-audit.txt`. Inspect for any unwanted sensitive identifiers
before sharing it. This is an **inventory**, NOT a fix or pass/fail verdict.

## Current conclusion

There is no evidence in these user-provided logs that the underlying RC3
kernel needs a new build to address the *root manager application* being
visible. A modified kernel with active root privileges cannot honestly be
declared "root-free" merely because a detector stops reporting an item.
Don't risk regressions to TEE or financial app data by deploying experimental
stealth kernels or manually editing attestation secrets.
