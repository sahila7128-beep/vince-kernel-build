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


# Linux 4.9 uses direct ARM64 x0-x5 arguments in the syscall table.
# These helpers restore the correct original-syscall calling convention.
replace("hook/syscall_hook.h",
    "extern syscall_fn_t *ksu_syscall_table;",
    """extern syscall_fn_t *ksu_syscall_table;
#if defined(__aarch64__) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline long ksu_invoke_original(int nr, const struct pt_regs *r)
{
    return ksu_syscall_table[nr](r->regs[0], r->regs[1], r->regs[2],
                                 r->regs[3], r->regs[4], r->regs[5]);
}
#else
static inline long ksu_invoke_original(int nr, const struct pt_regs *r)
{
    return ksu_syscall_table[nr](r);
}
#endif""")
for rel in ("feature/sucompat.c", "hook/syscall_event_bridge.c"):
    p = f/rel
    code = p.read_text()
    n = code.count("ksu_syscall_table[orig_nr](regs)")
    if n < 1:
        raise SystemExit(f"Expected original syscall invocations in {rel}")
    code = code.replace("ksu_syscall_table[orig_nr](regs)",
                        "ksu_invoke_original(orig_nr, regs)")
    if rel == "feature/sucompat.c":
        assert code.count("ksu_syscall_table[__NR_execveat](regs)") == 1
        code = code.replace("ksu_syscall_table[__NR_execveat](regs)",
                            "ksu_invoke_original(__NR_execveat, regs)")
    p.write_text(code)
    print(f"[compat49] adapted {rel}: {n} syscall call sites")

# Preserve "nofault" behavior by disabling user page faults around legacy
# strncpy_from_user, rather than silently substituting faultable reads.
p = f/"feature/sucompat.c"
src = p.read_text()
anchor49 = '#define SU_PATH "/system/bin/su"'
assert src.count(anchor49)==1
shim = """#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static inline long ksu_strncpy_from_user_nofault_49(char *dst,
    const char __user *src, long size)
{
    long ret;
    pagefault_disable();
    ret = strncpy_from_user(dst, src, size);
    pagefault_enable();
    return ret;
}
#define strncpy_from_user_nofault ksu_strncpy_from_user_nofault_49
#endif

"""
src=src.replace(anchor49,shim+anchor49,1)
p.write_text(src)

replace("feature/uts_view.c", "#include <linux/sched/signal.h>",
    "#include <linux/sched.h>")
print("[compat49] syscall forwarding is adjusted for 4.9; tracepoint dispatch itself still NOT validated.")


# Linux 4.9 LSM uses struct list_head rather than hlist_head. Never patch
# the head itself: only substitute an existing security_hook_list's func slot.
# This retains list integrity and fails closed for empty heads.
p=f/"hook/lsm_hook.c"
code=p.read_text()
target='''#else
    heads_addr = find_kernel_symbol_exact("security_hook_heads");'''
assert code.count(target)==1, "old LSM scan anchor changed"
legacy=r'''#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    heads_addr = find_kernel_symbol_exact("security_hook_heads");
    if (!heads_addr) {
        pr_err("lsm_hook: security_hook_heads missing\n");
        ret = -ENOENT;
        goto out_unlock;
    }
    {
        struct list_head *cursor;
        struct list_head *end;
        unsigned long heads_size = sizeof(struct security_hook_heads);
        unsigned long index;
        unsigned long count;

        if (heads_size % sizeof(struct list_head)) {
            ret = -EINVAL;
            goto out_unlock;
        }
        count = heads_size / sizeof(struct list_head);
        cursor = (struct list_head *)heads_addr;
        end = cursor + count;
        for (; cursor < end; cursor++) {
            list_for_each_entry(entry, cursor, list) {
                void **candidate = (void **)((char *)entry + hook->hook_offset);
                void *origin = READ_ONCE(*candidate);
                int j;
                for (j = 0; j < ksu_lsm_hook_count; j++) {
                    if (ksu_lsm_hook_entries[j].hook->replacement == origin) {
                        origin = ksu_lsm_hook_entries[j].hook->original;
                        break;
                    }
                }
                if (origin == hook->replacement) {
                    ret = -EALREADY;
                    goto out_unlock;
                }
                if (origin == target) {
                    selected_entry = entry;
                    selected_slot = candidate;
                    selected_origin = origin;
                    break;
                }
            }
            if (!selected_entry)
                continue;
            if (hook->offset) {
                index = (unsigned long)(cursor - (struct list_head *)heads_addr);
                if (hook->offset < 0 || (unsigned long)hook->offset >= count - index) {
                    ret = -EINVAL;
                    goto out_unlock;
                }
                cursor = (struct list_head *)heads_addr + index + hook->offset;
                if (list_empty(cursor)) {
                    pr_err("lsm_hook: empty legacy LSM head; refusing unsafe insertion\n");
                    ret = -ENOENT;
                    goto out_unlock;
                }
                entry = list_first_entry(cursor, struct security_hook_list, list);
                selected_entry = entry;
                selected_slot = (void **)((char *)entry + hook->hook_offset);
                selected_origin = READ_ONCE(*selected_slot);
            }
            break;
        }
        if (!selected_entry) {
            ret = -ENOENT;
            goto out_unlock;
        }
        ret = ksu_lsm_hook_track(hook);
        if (ret)
            goto out_unlock;
        ret = ksu_lsm_hook_patch_slot(selected_slot, hook->replacement);
        if (ret) {
            ksu_lsm_hook_untrack(hook);
            goto out_unlock;
        }
        hook->entry = selected_entry;
        hook->original = selected_origin;
        pr_info("lsm_hook: 4.9 legacy list hook installed: %s\n",
                hook->head_name ?: "unknown");
    }
#else
    heads_addr = find_kernel_symbol_exact("security_hook_heads");'''
code=code.replace(target,legacy,1)
end_anchor='''#endif
    goto out_unlock;
out_untrack:'''
assert code.count(end_anchor)==1,"LSM closing anchor changed"
code=code.replace(end_anchor,'''#endif
#endif
    goto out_unlock;
out_untrack:''',1)
unhook_start='''    if (hook->entry == &hook->list) {
        slot = (void **)&hook->list.head->first;'''
assert code.count(unhook_start)==1,"LSM unhook branch changed"
code=code.replace(unhook_start,'''#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    /* Legacy mode never inserts a hook node into the LSM list. */
    slot = (void **)((char *)hook->entry + hook->hook_offset);
#else
    if (hook->entry == &hook->list) {
        slot = (void **)&hook->list.head->first;''',1)
unhook_end=r'''        pr_info("unhook patch slot\n");
    }
#endif'''
assert code.count(unhook_end)==1,"LSM unhook end changed"
code=code.replace(unhook_end,r'''        pr_info("unhook patch slot\n");
    }
#endif
#endif''',1)
p.write_text(code)
print("[compat49] 4.9 legacy LSM list adapter, no dynamic head insertion")

replace("hook/setuid_hook.c", "#include <linux/sched/signal.h>",
        "#include <linux/sched.h>")

print("[compat49] ABI/header compile adapters applied. Runtime safety NOT established.")
