#!/usr/bin/env python3
"""Fail-closed source audit. This is NOT a phone/DirtySepolicy/banking runtime test."""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT_COMMIT = "24cc758fec61d44c45cafeea4c844fd0856f71c9"
CHECKS = (
    ("ROOT_FILE_TYPE", "selinux/selinux.h", r'^\s*#define\s+KERNEL_SU_FILE\s+"ksu_file"', True),
    ("LEGACY_MANAGER_IOCTL_UAPI0", "supercalls.h", r"^\s*#define\s+KSU_IOCTL_GET_INFO\s+_IOC\(_IOC_READ,\s*'K',\s*2,\s*0\)", True),\n
    ("ROOT_DOMAIN", "selinux/selinux.h", r'^\s*#define\s+KERNEL_SU_DOMAIN\s+"(?:su|ksu)"', False),
    ("CREATES_ROOT_FILE_TYPE", "selinux/rules.c", r'ksu_type\s*\(\s*db\s*,\s*KERNEL_SU_FILE', True),
    ("PERMISSIVE_ROOT_DOMAIN", "selinux/rules.c", r'ksu_permissive\s*\(\s*db\s*,\s*KERNEL_SU_DOMAIN\s*\)', True),
    ("BROAD_ROOT_ALLOW", "selinux/rules.c", r'ksu_allow\s*\(\s*db\s*,\s*KERNEL_SU_DOMAIN\s*,\s*ALL\s*,\s*ALL\s*,\s*ALL\s*\)', True),
    ("BROAD_FILE_ALLOW", "selinux/rules.c", r'ksu_allow\s*\(\s*db\s*,\s*ALL\s*,\s*KERNEL_SU_FILE\s*,\s*ALL\s*,\s*ALL\s*\)', True),
    ("DYNAMIC_POLICY_API", "selinux/rules.c", r'int\s+handle_sepolicy\s*\(', False),
)

def inspect(root):
    required = {filename for _, filename, _, _ in CHECKS}
    for filename in required:
        if not (root / filename).is_file():
            raise FileNotFoundError("Missing pinned root source: " + filename)
    findings = []
    for code, filename, expression, blocker in CHECKS:
        source = (root / filename).read_text(encoding="utf-8", errors="replace")
        match = re.search(expression, source, re.MULTILINE)
        if match:
            findings.append(dict(code=code, path=filename,
                                 line=source.count("\n", 0, match.start()) + 1,
                                 blocker=blocker))
    return dict(device="vince", root_commit=ROOT_COMMIT,
                static_findings=findings,
                static_blockers=sum(bool(x["blocker"]) for x in findings),
                source_status="FAIL" if any(x["blocker"] for x in findings) else "INCONCLUSIVE",
                final_release="NOT_READY",
                live_dirtysepolicy_zero_verified=False,
                selinux_enforcing_device_verified=False,
                recovery_flash_device_verified=False,
                root_and_modules_device_verified=False,
                banking_apps_device_verified=False,
                detector_source="https://github.com/LSPosed/DirtySepolicy",
                caveats=[
                  "ksu_file is an explicit SELinux context marker checked by DirtySepolicy.",
                  "Pinned root uses legacy zero-sized GET_INFO ioctl. Manager v4.2.0-rc3 uses a size-encoded GET_INFO and sets kernel UAPI to 0 after fallback; never claim full-featured API 4.",
                  "This source audit does not run Android, a banking app or a real recovery.",
                  "Eliminating one marker does not prove no root leaks; source absence never equals runtime PASS.",
                  "Never falsify SELinux queries or detector responses to claim DirtySepolicy=0.",
                ])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--markdown", type=Path, required=True)
    a=p.parse_args()
    try:
        r=inspect(a.root)
    except Exception as e:
        print("[BLOCKED] Source audit impossible:", e, file=sys.stderr)
        return 3
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.markdown.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(r, indent=2)+"\n")
    lines=["# Redmi 5 Plus / vince security release gate", "",
           "**NOT READY FOR FINAL FLASH**", "",
           "This is source analysis, not a phone test.", "",
           "Source blockers: "+str(r["static_blockers"]), "",
           "| Finding | Source | Blocks release |", "|---|---|---|"]
    for x in r["static_findings"]:
        lines.append("| "+x["code"]+" | "+x["path"]+":"+str(x["line"])+" | "+str(x["blocker"])+" |")
    lines += ["", "Must still test live DirtySepolicy, SELinux, Android boot, module installs, and actual m-banking app.", ""]
    a.markdown.write_text("\n".join(lines))
    print("FINAL_RELEASE=NOT_READY; static_blockers=",r["static_blockers"])
    for x in r["static_findings"]:
        print(("[BLOCKER] " if x["blocker"] else "[REVIEW] ")+x["code"]+" "+x["path"]+":"+str(x["line"]))
    return 2  # Deliberately fail closed: CI never grants phone tests.

if __name__ == "__main__":
    sys.exit(main())
