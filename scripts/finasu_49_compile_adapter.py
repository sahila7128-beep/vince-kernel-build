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

# All remaining linux/compiler_types.h includes in FinaSU v1.4.5.
replace("sulog/event.h", "#include <linux/compiler_types.h>",
        "#include <linux/compiler.h>")
replace("policy/allowlist.c", "#include <linux/compiler_types.h>",
        "#include <linux/compiler.h>")

# Keep UTS ABI layout checks active with compiler-native C11 syntax.
replace("feature/uts_view.c",
        "static_assert(sizeof(struct ksu_uts_view_config)",
        "_Static_assert(sizeof(struct ksu_uts_view_config)")

# More old header mappings that CI exposed.
replace("feature/sulog.c", "#include <linux/compiler_types.h>",
        "#include <linux/compiler.h>")

# Preserve compile-time ABI size assertions (use C11 spelling on 4.9).
p = f/"feature/netisolate.c"
src = p.read_text()
import re
src,n=re.subn(r"(?m)^static_assert\(", "_Static_assert(", src)
if n!=4:
    raise SystemExit(f"Expected 4 netisolate size assertions, found {n}")
src=src.replace('#include <linux/types.h>', '#include <linux/types.h>\n#include <linux/version.h>',1)
start=src.index("#define NI_WRAPPER(name, op, compat)")
stop=src.index("\nNI_WRAPPER(ni_connect, NI_CONNECT, false)",start)
existing=src[start:stop]
legacy="""#if defined(__aarch64__) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
/* On 4.9 arm64 sys_call_table takes original x0-x5 argument registers,
 * never a struct pt_regs * like newer syscall wrappers. */
#define NI_WRAPPER(name, op, compat) \\
    static long __nocfi name(unsigned long a0, unsigned long a1, \\
                            unsigned long a2, unsigned long a3, \\
                            unsigned long a4, unsigned long a5) \\
    { \\
        struct pt_regs reg_copy = { 0 }; \\
        struct ni_endpoint endpoint; \\
        reg_copy.regs[0] = a0; reg_copy.regs[1] = a1; \\
        reg_copy.regs[2] = a2; reg_copy.regs[3] = a3; \\
        reg_copy.regs[4] = a4; reg_copy.regs[5] = a5; \\
        if (ni_should_refuse(&reg_copy, op, compat, &endpoint)) { \\
            ni_record_event(current_uid().val, op, &endpoint); \\
            return op == NI_SOCKET ? -EACCES : -ECONNREFUSED; \\
        } \\
        return ni_original(op, compat)(a0, a1, a2, a3, a4, a5); \\
    }
#else
"""
src=src[:start]+legacy+existing+"\n#endif\n"+src[stop:]
p.write_text(src)
print("[compat49] netisolate ABI wrappers and size assertions adapted; runtime still UNTESTED")

print("[compat49] ABI/header compile adapters applied. Runtime safety NOT established.")
