#!/usr/bin/env python3
"""Compile-time compatibility probes for upstream FinaSU v1.4.5 on Linux 4.9.
Not sufficient for safe boot: the tracepoint dispatcher requires arm64 syscall
ABI validation before any image may be released.
Every edit is exact-match and fails closed on unknown upstream revisions.
"""
import sys
from pathlib import Path

k = Path(sys.argv[1])
f = k/"drivers/kernelsu"
assert f.exists()

def replace(rel, old, new):
    p=f/rel
    s=p.read_text()
    hits=s.count(old)
    if hits!=1:
        raise SystemExit(f"FinaSU 4.9 adapter: {rel}: expected one anchor, got {hits}: {old[:85]!r}")
    p.write_text(s.replace(old,new,1))
    print(f"[compat49] patched {rel}")

# Old ARM64 sys_call_table contains direct x0-x5 argument functions,
# NOT the modern pt_regs syscall wrappers. This typedef mirrors the old
# underlying ABI, but DOES NOT make the tracepoint dispatcher compatible.
replace("hook/syscall_hook.h",
        "#elif defined(__riscv)\ntypedef long (*syscall_fn_t)(const struct pt_regs *);",
        """#elif defined(__aarch64__)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
typedef asmlinkage long (*syscall_fn_t)(unsigned long, unsigned long,
    unsigned long, unsigned long, unsigned long, unsigned long);
#else
typedef long (*syscall_fn_t)(const struct pt_regs *);
#endif
#elif defined(__riscv)
typedef long (*syscall_fn_t)(const struct pt_regs *);""")

# MODULE_IMPORT_NS was introduced after Linux 4.9; its old compatibility
# branch must not emit an undefined top-level macro.
replace("core/init.c",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)\nMODULE_IMPORT_NS(\"VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver\");",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)\nMODULE_IMPORT_NS(\"VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver\");")
replace("core/init.c",
        "#else\nMODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);\n#endif",
        "#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)\nMODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);\n#endif")

# Kernel 4.9 printk ratelimit macros require an explicit dependency.
replace("feature/kernel_umount.c", "#include <linux/printk.h>",
        "#include <linux/printk.h>\n#include <linux/ratelimit.h>")

# Legacy 4.9 headers. These replacements change includes only.
replace("feature/sucompat.c", "#include <linux/compiler_types.h>",
        "#include <linux/compiler.h>")
replace("feature/sucompat.c", "#include <linux/pgtable.h>",
        "#include <asm/pgtable.h>")
for rel in ("feature/sucompat.c","hook/syscall_hook_manager.c"):
    replace(rel, "#include <linux/sched/task_stack.h>",
            "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)\n#include <linux/sched/task_stack.h>\n#else\n#include <linux/sched.h>\n#endif")

print("[compat49] ABI/header compile adapters applied. Runtime safety NOT established.")
