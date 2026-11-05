#!/usr/bin/env python3
"""Strict vendor-specific SUSFS 2.3.0 adaptations for ZeroTwo 4.9.337.
Only used after upstream patch application has passed git apply --check.
"""
from pathlib import Path
import re
import subprocess
import sys

SKIP = {"fs/proc/cmdline.c", "kernel/sys.c"}


def once(src, old, new, name):
    count = src.count(old)
    if count != 1:
        raise RuntimeError(f"{name}: expected unique anchor; found {count}: {old[:90]!r}")
    return src.replace(old, new, 1)


def patch_cmdline(src):
    src = once(src, "#include <linux/seq_file.h>\n",
        "#include <linux/seq_file.h>\n#include <linux/jump_label.h>\n"
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
        "extern struct static_key_false susfs_is_fake_cmdline_or_bootconfig_buffer_set;\n"
        "extern void susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);\n"
        "#endif\n", "fs/proc/cmdline.c")
    marker = "static int cmdline_proc_show(struct seq_file *m, void *v)\n{\n"
    return once(src, marker, marker +
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
        "    if (static_branch_likely(&susfs_is_fake_cmdline_or_bootconfig_buffer_set)) {\n"
        "        susfs_spoof_cmdline_or_bootconfig(m);\n"
        "        return 0;\n"
        "    }\n"
        "#endif\n", "fs/proc/cmdline.c")


def patch_sys(src):
    marker = "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n"
    src = once(src, marker, "#ifdef CONFIG_KSU_SUSFS\n"
        "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n"
        "#endif\n" + marker, "kernel/sys.c")
    src = once(src, "\tkuid_t kruid, keuid, ksuid;\n\n\tkruid = make_kuid(ns, ruid);",
        "\tkuid_t kruid, keuid, ksuid;\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\t(void)ksu_handle_setresuid(ruid, euid, suid);\n"
        "#endif\n\n\tkruid = make_kuid(ns, ruid);", "kernel/sys.c")
    marker = "SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)\n{\n\tstruct new_utsname tmp;\n"
    src = once(src, marker,
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "extern struct static_key_false susfs_is_uname_spoof_buffer_set;\n"
        "extern void susfs_spoof_uname(struct new_utsname *tmp);\n"
        "#endif\n" + marker +
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "\tbool susfs_uname_overridden = false;\n"
        "#endif\n", "kernel/sys.c")
    marker = "SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)\n{\n"
    start = src.index(marker)
    # Restrict replacements to the newuname function; other uname variants also contain memcpy.
    end = src.index("\n}\n", start) + len("\n}")
    block = src[start:end]
    block = once(block, "\tmemcpy(&tmp, utsname(), sizeof(tmp));\n\tup_read(&uts_sem);",
        "\tmemcpy(&tmp, utsname(), sizeof(tmp));\n"
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "\tif (static_branch_likely(&susfs_is_uname_spoof_buffer_set)) {\n"
        "\t\tsusfs_spoof_uname(&tmp);\n"
        "\t\tsusfs_uname_overridden = true;\n"
        "\t}\n"
        "#endif\n"
        "\tup_read(&uts_sem);", "kernel/sys.c")
    block = once(block, "\toverride_custom_release(name->release, sizeof(name->release));",
        "#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
        "\tif (susfs_uname_overridden)\n"
        "\t\treturn 0;\n"
        "#endif\n"
        "\toverride_custom_release(name->release, sizeof(name->release));", "kernel/sys.c")
    return src[:start] + block + src[end:]


def main(kernel, upstream):
    kernel = Path(kernel).resolve()
    patch = Path(upstream).read_text()
    chunks = re.split(r"(?=^diff --git a/)", patch, flags=re.MULTILINE)
    retained, excluded = [], set()
    for chunk in chunks:
        match = re.match(r"diff --git a/\S+ b/(\S+)", chunk)
        if match and match.group(1) in SKIP:
            excluded.add(match.group(1))
        else:
            retained.append(chunk)
    if excluded != SKIP:
        raise RuntimeError(f"Missing vendor override sections: {SKIP - excluded}")
    filtered = kernel / ".susfs-zerotwo-filtered.patch"
    filtered.write_text("".join(retained))
    subprocess.run(["git", "apply", "--check", "--whitespace=nowarn", str(filtered)], cwd=kernel, check=True)
    subprocess.run(["git", "apply", "--whitespace=nowarn", str(filtered)], cwd=kernel, check=True)
    filtered.unlink()
    for path, adapter in (("fs/proc/cmdline.c", patch_cmdline), ("kernel/sys.c", patch_sys)):
        f = kernel / path
        f.write_text(adapter(f.read_text()))
        print(f"[+] Applied specific SUSFS adapter: {path}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: vendor_fix.py KERNEL_ROOT SUSFS_PATCH")
    main(sys.argv[1], sys.argv[2])
