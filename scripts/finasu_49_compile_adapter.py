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
replace("hook/tp_marker.c", "#include <linux/sched/signal.h>",
        "#include <linux/sched.h>")
replace("sulog/event.c", "#include <linux/sched/signal.h>",
        "#include <linux/sched.h>")
replace("policy/app_profile.c", "#include <linux/sched/signal.h>",
        "#include <linux/sched.h>")
replace("infra/symbol_resolver.c", "#include <linux/sched/signal.h>",
        "#include <linux/sched.h>")
replace("hook/tp_marker.c", "#include <linux/sched/task.h>",
        "#include <linux/sched.h>")
replace("infra/seccomp_cache.c", "#include <linux/sched/task.h>",
        "#include <linux/sched.h>")
replace("infra/su_mount_ns.c", "#include <linux/sched/task.h>",
        "#include <linux/sched.h>")
replace("feature/selinux_hide.c", "#include <linux/sched/task.h>",
        "#include <linux/sched.h>")


# Kernel 4.9 ARM64 header does not transitively include version macros.
replace("hook/syscall_hook.h", "#include <asm/syscall.h>",
        "#include <asm/syscall.h>\n#include <linux/version.h>")

# Critical runtime ABI correction: Linux 4.9 ARM64 loads syscall handlers
# from sys_call_table with six direct arguments, not struct pt_regs *.
# The dispatcher must obtain pt_regs from current's syscall stack.
replace("hook/arm64/syscall_hook.c",
        "#include <linux/kallsyms.h>",
        "#include <linux/kallsyms.h>\n#include <linux/sched.h>\n#include <linux/version.h>")
replace("hook/arm64/syscall_hook.c",
        '"__arm64_sys_ni_syscall"',
        '(LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) ? '
        '"sys_ni_syscall" : "__arm64_sys_ni_syscall")')
replace("hook/arm64/syscall_hook.c",
        "static long __nocfi ksu_syscall_dispatcher(const struct pt_regs *regs)\n{",
        "static long __nocfi ksu_syscall_dispatcher_regs(const struct pt_regs *regs)\n{")
replace("hook/arm64/syscall_hook.c",
        '''    return ret;
}

// Register a handler into the dispatcher's routing table.''',
        '''    return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static long __nocfi ksu_syscall_dispatcher(unsigned long a0,
       unsigned long a1, unsigned long a2, unsigned long a3,
       unsigned long a4, unsigned long a5)
{
    /* The 4.9 entry assembly pushes user regs to the current task stack
     * before invoking sys_call_table[nr] with x0..x5. Never treat x0 as
     * a pt_regs pointer. The original nr was stashed in saved x8. */
    const struct pt_regs *regs = task_pt_regs(current);
    if (unlikely(!regs || regs->syscallno != ksu_dispatcher_nr))
        return -ENOSYS;
    return ksu_syscall_dispatcher_regs(regs);
}
#else
static long __nocfi ksu_syscall_dispatcher(const struct pt_regs *regs)
{
    return ksu_syscall_dispatcher_regs(regs);
}
#endif

// Register a handler into the dispatcher's routing table.''')
print("[compat49] arm64 syscall dispatcher now uses six-direct-arg Linux 4.9 ABI")


# Legacy arm64 page table walker: pre-4.14 does not have p4d. Use the
# existing pgd->pud->pmd->pte walk and explicitly handle section mappings.
p=f/"hook/arm64/patch_memory.c"
src=p.read_text()
assert src.count('#include "asm/cacheflush.h"')==1
src=src.replace('#include "asm/cacheflush.h"',
                '#include "asm/cacheflush.h"\n#include <linux/version.h>',1)
assert src.count('    p4d_t *p4d;')==1
src=src.replace('    p4d_t *p4d;',
    '#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)\n    p4d_t *p4d;\n#endif',1)
a=src.index("    p4d = p4d_offset(pgd, addr);")
b=src.index("    if (pud_none(*pud) || pud_bad(*pud))",a)
src=src[:a] + (
    '#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)\n'
    '    pud = pud_offset(pgd, addr);\n'
    '#else\n' + src[a:b] + '#endif\n'
) + src[b:]
old='''    if (pud_none(*pud) || pud_bad(*pud))
        goto fail;'''
new='''#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    if (pud_none(*pud))
        goto fail;
    if (pud_sect(*pud))
        return ((phys_addr_t)pud_pfn(*pud) << PAGE_SHIFT) + (addr & ~PUD_MASK);
    if (pud_bad(*pud))
        goto fail;
#else
    if (pud_none(*pud) || pud_bad(*pud))
        goto fail;
#endif'''
assert src.count(old)==1
src=src.replace(old,new,1)
old='''    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto fail;'''
new='''#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    if (pmd_sect(*pmd))
        return ((phys_addr_t)pmd_pfn(*pmd) << PAGE_SHIFT) + (addr & ~PMD_MASK);
#endif
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto fail;'''
assert src.count(old)==1
src=src.replace(old,new,1)
old='''    return __pte_to_phys(*pte) + ((addr & ~PAGE_MASK));'''
new='''#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    return ((phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT) + (addr & ~PAGE_MASK);
#else
    return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);
#endif'''
assert src.count(old)==1
src=src.replace(old,new,1)
old='''#define ksu_flush_icache(start, end) __flush_icache_range(start, end)'''
new='''#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define ksu_flush_icache(start, end) flush_icache_range(start, end)
#else
#define ksu_flush_icache(start, end) __flush_icache_range(start, end)
#endif'''
assert src.count(old)==1
src=src.replace(old,new,1)
old='''    ret = (int)copy_to_kernel_nofault(map, src, len);'''
new='''#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
    ret = (int)probe_kernel_write(map, src, len);
#else
    ret = (int)copy_to_kernel_nofault(map, src, len);
#endif'''
assert src.count(old)==1
src=src.replace(old,new,1)
p.write_text(src)
print("[compat49] old arm64 pgtable and text poke APIs; hardware runtime NOT tested")

# The Vivo init_module/finit_module filter also directly hooks the native
# syscall table; old 4.9 needs the 6-direct-register-argument convention.
p=f/"hook/init_module_filter.c"
src=p.read_text()
old='''static long (*orig_init_module)(const struct pt_regs *regs);
static long (*orig_finit_module)(const struct pt_regs *regs);'''
new='''#if defined(__aarch64__) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static syscall_fn_t orig_init_module;
static syscall_fn_t orig_finit_module;
#else
static long (*orig_init_module)(const struct pt_regs *regs);
static long (*orig_finit_module)(const struct pt_regs *regs);
#endif'''
assert src.count(old)==1
src=src.replace(old,new,1)
start=src.index("static long filter_init_module(const struct pt_regs *regs)")
end=src.index("void __init ksu_init_module_filter_init(void)",start)
legacy=r'''#if defined(__aarch64__) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define KSU_49_MODULE_FILTER(name, matcher, original) \
    static long name(unsigned long a0, unsigned long a1, \
                     unsigned long a2, unsigned long a3, \
                     unsigned long a4, unsigned long a5) \
    { \
        struct pt_regs regs = { 0 }; \
        regs.regs[0] = a0; regs.regs[1] = a1; \
        regs.regs[2] = a2; regs.regs[3] = a3; \
        regs.regs[4] = a4; regs.regs[5] = a5; \
        if (capable(CAP_SYS_MODULE) && matcher(&regs)) { \
            pr_info("init_module_filter: acknowledged compatible target module\n"); \
            return 0; \
        } \
        return original(a0, a1, a2, a3, a4, a5); \
    }
KSU_49_MODULE_FILTER(filter_init_module, init_module_matches, orig_init_module)
KSU_49_MODULE_FILTER(filter_finit_module, finit_module_matches, orig_finit_module)
#undef KSU_49_MODULE_FILTER
#else
'''
src=src[:start]+legacy+src[start:end]+'#endif\n\n'+src[end:]
src=src.replace('#include <linux/version.h>', '#include <linux/version.h>',1)
# FinaSU already includes linux/version.h in include/arch.h.
p.write_text(src)
print("[compat49] init_module syscall-filter original-call ABI matched to 4.9")

print("[compat49] ABI/header compile adapters applied. Runtime safety NOT established.")


# ---------------------------------------------------------------------------
# FinaSU v1.4.5 Linux 4.9 infra adapters based on CI 42258307048.
# No globally permissive SELinux rules and no silent feature removal.
# ---------------------------------------------------------------------------
replace("infra/event_queue.h",
        "#include <linux/fs.h>",
        "#include <linux/fs.h>\n#include <linux/version.h>\n"
        "#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)\n"
        "typedef unsigned int __poll_t;\n#endif")
p = f/"infra/event_queue.c"
s = p.read_text()
assert s.count("EPOLLHUP | POLLHUP") == 3
assert s.count("EPOLLIN | EPOLLRDNORM") == 2
s = s.replace("EPOLLHUP | POLLHUP", "POLLHUP")
s = s.replace("EPOLLIN | EPOLLRDNORM", "POLLIN | POLLRDNORM")
assert s.count("struct_size(node, payload, len)") == 1
s = s.replace("struct_size(node, payload, len)", "sizeof(*node) + len")
p.write_text(s)
print("[compat49] event queue: legacy poll mask/type and allocation")

p = f/"infra/file_wrapper.c"
s = p.read_text()
def fw_once(old, new):
    global s
    assert s.count(old)==1, f"file_wrapper: unexpected anchor count: {old[:85]!r}"
    s = s.replace(old, new, 1)

fw_once("#include <linux/mount.h>", "#include <linux/mount.h>\n#include <linux/module.h>")
fw_once("static __poll_t ksu_wrapper_poll", "static unsigned int ksu_wrapper_poll")

# iopoll is absent on Linux 4.9, so its wrapper must not be assigned.
start = s.index("#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)\nstatic int ksu_wrapper_iopoll")
stop  = s.index("#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)\nstatic int ksu_wrapper_iterate",start)
s=s[:start]+"#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)\n"+s[start:stop]+"#endif\n\n"+s[stop:]
fw_once("    p->ops.iopoll = fp->f_op->iopoll ? ksu_wrapper_iopoll : NULL;",
    "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)\n"
    "    p->ops.iopoll = fp->f_op->iopoll ? ksu_wrapper_iopoll : NULL;\n#endif")

fw_once("#else\n    p->ops.mmap_supported_flags = fp->f_op->mmap_supported_flags;\n#endif",
    "#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)\n"
    "    p->ops.mmap_supported_flags = fp->f_op->mmap_supported_flags;\n#endif")

# Only dispatch methods that exist in the 4.9 file_operations ABI.
start = s.index("static loff_t ksu_wrapper_remap_file_range")
stop = s.index("static void ksu_release_file_wrapper", start)
s=s[:start] + "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)\n" + s[start:stop] + "#endif\n\n" + s[stop:]
fw_once("    p->ops.remap_file_range = fp->f_op->remap_file_range ? ksu_wrapper_remap_file_range : NULL;\n    p->ops.fadvise = fp->f_op->fadvise ? ksu_wrapper_fadvise : NULL;",
    "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)\n"
    "    p->ops.remap_file_range = fp->f_op->remap_file_range ? ksu_wrapper_remap_file_range : NULL;\n"
    "    p->ops.fadvise = fp->f_op->fadvise ? ksu_wrapper_fadvise : NULL;\n#endif")

# Linux 4.9 lacks alloc_file_pseudo and inode_init_security_anon.
# Backport a PER-FD inode using 4.9's own anon_inode_getfile primitives.
# Never use anon_inode_getfile() directly: it shares a global inode and
# re-labeling that would change SELinux metadata for unrelated descriptors.
start = s.index("static struct inode *ksu_anon_inode_make_secure_inode")
stop = s.index("\n#endif\n\nint ksu_install_file_wrapper",start)
legacy = r"""
static struct file *ksu_anon_inode_create_getfile_compat(const char *name,
      const struct file_operations *fops, void *priv, int flags,
      const struct inode *context_inode)
{
    struct inode *inode;
    struct dentry *dentry;
    struct path path;
    struct file *file;
    struct qstr qname;
    struct inode_security_struct *isec;

    (void)context_inode;
    if (unlikely(!anon_inode_mnt))
        return ERR_PTR(-ENODEV);
    if (fops->owner && !try_module_get(fops->owner))
        return ERR_PTR(-ENOENT);

    inode = alloc_anon_inode(anon_inode_mnt->mnt_sb);
    if (IS_ERR(inode)) {
        file = ERR_CAST(inode);
        goto err_module;
    }

    inode->i_flags &= ~S_PRIVATE;
    /* Label the unique inode before publishing it via fd_install(). */
    isec = ksu_selinux_inode(inode);
    if (IS_ERR(isec)) {
        file = ERR_CAST(isec);
        goto err_inode;
    }
    if (!isec) {
        file = ERR_PTR(-EACCES);
        goto err_inode;
    }
    isec->sid = ksu_file_sid;

    qname.name = name;
    qname.len = strlen(name);
    qname.hash = 0;
    dentry = d_alloc_pseudo(anon_inode_mnt->mnt_sb, &qname);
    if (!dentry) {
        file = ERR_PTR(-ENOMEM);
        goto err_inode;
    }

    path.dentry = dentry;
    path.mnt = mntget(anon_inode_mnt);
    d_instantiate(dentry, inode);
    file = alloc_file(&path, OPEN_FMODE(flags), fops);
    if (IS_ERR(file))
        goto err_path;

    file->f_mapping = inode->i_mapping;
    file->f_flags = flags & (O_ACCMODE | O_NONBLOCK);
    file->private_data = priv;
    return file;

err_path:
    path_put(&path);
    goto err_module;
err_inode:
    iput(inode);
err_module:
    module_put(fops->owner);
    return file;
}
"""
s=s[:start]+legacy+s[stop:]
p.write_text(s)
print("[compat49] private per-file anon inode with Linux 4.9 alloc_file ABI; runtime unvalidated")


# ---------------------------------------------------------------------------
# Linux 4.9 seccomp and mount namespace shims (CI 42309703536).
# Linux 4.9's struct seccomp_filter has *no action cache*, so cache invalidation
# is intentionally empty on this ABI; the actual seccomp BPF still evaluates.
# ---------------------------------------------------------------------------
p=f/"infra/seccomp_cache.c"
s=p.read_text()
s="#include <linux/version.h>\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)\n" + """\
#include <linux/types.h>
#include <linux/seccomp.h>
#include "infra/seccomp_cache.h"

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter; (void)nr; /* 4.9 has no cached seccomp allow decision */
}
void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter; (void)nr; /* 4.9 evaluates BPF at every decision */
}
#else
""" + s + "\n#endif\n"
p.write_text(s)
print("[compat49] original 4.9 seccomp BPF has no action cache to invalidate")

p=f/"infra/su_mount_ns.c"
s=p.read_text()
assert s.count("#include <uapi/linux/mount.h>")==1
s=s.replace("#include <uapi/linux/mount.h>",
    "#include <linux/mount.h>\n#include <linux/uaccess.h>",1)
before="""    struct path root_path;
    get_fs_root(current->fs, &root_path);
    int pm_ret = path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);
    path_put(&root_path);"""
assert s.count(before)==1
after="""#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    /* 4.9 has no path_mount(). Only the thread-local address limit is
     * raised for the legacy mount syscall; restore it on every path. */
    mm_segment_t old_fs = get_fs();
    int pm_ret;
    set_fs(KERNEL_DS);
    pm_ret = ksyscall(mount, NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
    set_fs(old_fs);
#else
""" + before + "\n#endif"
s=s.replace(before,after,1)
p.write_text(s)
print("[compat49] mount namespace: 4.9 mount syscall with restored address limit")
