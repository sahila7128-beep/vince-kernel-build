#!/usr/bin/env bash
# Linux 4.9 port feasibility probe for ReSukiSU + SUSFS 2.3.0.
# This remains UNTESTED on physical vince; CI success is NOT a boot certificate.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/work"
OUT="$ROOT/artifacts"
mkdir -p "$WORK" "$OUT"
trap 'echo "[FAILED] Inspect build log at line $LINENO" >&2' ERR

# Pinned sources -- reproducible and no moving main branch.
KERNEL=609a588f30d61a7f04e2061ab59c4f9c8c49aa6d
ROOT_SU=24cc758fec61d44c45cafeea4c844fd0856f71c9
SUSFS=71345ded5af28f55d76ebcdc7a9df9cea56111e1
ANYKERNEL=783f109bdbcacfea6e4c7bc232437afe796fae28
NOMOUNT=07efa370edb784327ee03877c9882ab2599a15ce

get_source() {
 local url="$1" dest="$2" sha="$3"
 echo "[+] Fetch $url @ $sha"
 git init -q "$dest"
 git -C "$dest" remote add origin "$url"
 git -C "$dest" fetch --depth=1 origin "$sha"
 git -C "$dest" -c advice.detachedHead=false checkout --detach -q FETCH_HEAD
 test "$(git -C "$dest" rev-parse HEAD)" = "$sha"
}
get_source https://github.com/rahmatsobrian/kernel_xiaomi_vince_4.9.337_zerotwo.git "$WORK/ZeroTwo" "$KERNEL"
get_source https://github.com/xixiaobei-bei/ReSukiSU.git "$WORK/ReSukiSU" "$ROOT_SU"
get_source https://github.com/wxx9248/susfs4ksu.git "$WORK/susfs4ksu" "$SUSFS"
get_source https://github.com/maxsteeel/nomount.git "$WORK/NoMount" "$NOMOUNT"
K="$WORK/ZeroTwo"
P="$WORK/susfs4ksu/kernel_patches"

# Use exactly one KernelSU implementation.
test ! -e "$K/drivers/kernelsu"
ln -s ../../ReSukiSU/kernel "$K/drivers/kernelsu"
# Linux 4.9 SELinux's flask.h / av_permissions.h are generated under
# $(objtree)/security/selinux, while ReSukiSU's include flags normally only
# cover the source directories. Keep the generated headers in the search path.
grep -Fq 'ccflags-y += -I$(srctree)/security/selinux' "$WORK/ReSukiSU/kernel/Kbuild"
printf '\nccflags-y += -I$(objtree)/security/selinux\n' >> "$WORK/ReSukiSU/kernel/Kbuild"
printf '\nobj-$(CONFIG_KSU) += kernelsu/\n' >> "$K/drivers/Makefile"
python3 - "$K/drivers/Kconfig" <<'PY'
from pathlib import Path
import sys
f=Path(sys.argv[1]); s=f.read_text()
anchor="\nendmenu\n"
assert s.count(anchor)==1, "Unexpected drivers/Kconfig layout"
f.write_text(s.replace(anchor, '\nsource "drivers/kernelsu/Kconfig"\n'+anchor))
PY

for f in fs/susfs.c include/linux/susfs.h include/linux/susfs_def.h; do
 test -s "$P/$f"
 cp "$P/$f" "$K/$f"
done
python3 "$ROOT/scripts/vendor_fix.py" "$K" "$P/50_add_susfs_in_kernel-4.9.patch"

# Linkage fixes for the 4.9 SUSFS patch versus the ReSukiSU v24cc API.
# Do not create permanent always-on hooks or disable root-module features.
python3 - "$K" "$WORK/ReSukiSU/kernel" <<'PY'
from pathlib import Path
import sys
k, su = map(Path, sys.argv[1:])

def exactly_once(path, before, after):
    s = path.read_text()
    count = s.count(before)
    if count != 1:
        raise SystemExit(f"SUSFS/ReSukiSU ABI mismatch: {path} {before[:75]!r} got={count}")
    path.write_text(s.replace(before, after, 1))

# SUSFS 4.9 patch refers to static keys from a newer root variant;
# ReSukiSU stores the SAME enabled/disabled state as regular exported booleans.
for name in ("fs/read_write.c", "fs/stat.c"):
    p = k / name
    exactly_once(p,
        "extern struct static_key_true ksu_is_init_rc_hook_enabled;",
        "extern bool ksu_init_rc_hook;")
    s = p.read_text()
    count = s.count("static_branch_unlikely(&ksu_is_init_rc_hook_enabled)")
    if count < 1:
        raise SystemExit(f"Missing init_rc hook access: {name}")
    p.write_text(s.replace("static_branch_unlikely(&ksu_is_init_rc_hook_enabled)",
                           "unlikely(READ_ONCE(ksu_init_rc_hook))"))
exactly_once(k/"drivers/input/input.c",
    "extern struct static_key_true ksu_is_input_hook_enabled;",
    "extern bool ksu_input_hook;")
exactly_once(k/"drivers/input/input.c",
    "static_branch_unlikely(&ksu_is_input_hook_enabled)",
    "unlikely(READ_ONCE(ksu_input_hook))")

# SUSFS source has the intended implementation but marks it file-local;
# ReSukiSU's unmount task-work needs to call it after unmounting.
exactly_once(k/"fs/susfs.c",
    "static void susfs_run_sus_path_loop(void) {",
    "void susfs_run_sus_path_loop(void) {")

# This 4.9 SUSFS port does not implement the Android-data/sdcard-root
# i_state API used by newer root clients. Never falsely report success.
# Explicitly reject these unsupported command IDs, preserving all APIs
# actually available in the pinned SUSFS 2.3.0 Linux 4.9 port.
p = su/"supercalls.c"
for name in ("CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH", "CMD_SUSFS_SET_SDCARD_ROOT_PATH"):
    before = ("if (cmd == " + name + ") {\n"
              "            susfs_set_i_state_on_external_dir(arg);\n"
              "            return 0;\n"
              "        }")
    after = ("if (cmd == " + name + ") {\n"
             "            pr_warn_ratelimited(\"SUSFS Linux 4.9: external root i_state API not implemented by pinned port\\n\");\n"
             "            return -EOPNOTSUPP;\n"
             "        }")
    exactly_once(p, before, after)

# Fail closed if modern static keys are still referenced.
for p in (k/"fs/read_write.c", k/"fs/stat.c", k/"drivers/input/input.c"):
    if "ksu_is_init_rc_hook_enabled" in p.read_text() or "ksu_is_input_hook_enabled" in p.read_text():
        raise SystemExit(f"Unresolved 4.9 hook symbol in {p}")
print("[+] Four LTO undefined symbols resolved using real legacy API or explicit unsupported errno")
PY

# Root integration here uses ReSukiSU's native Linux 4.9 legacy API.
# Do not load modern FinaSU syscall/SELinux compatibility shims into this build.

# Android 13 SELinux Netlink permission backport for ZeroTwo 4.9.
# The base kernel only exposes nlmsg_read/write for netlink_route_socket,
# while the installed Android 13 ROM declares nlmsg_readpriv/getneigh.
# Without these kernel mappings RTM_GETLINK and RTM_GETNEIGH both use the
# overly broad netdomain:nlmsg_read rule, exposing Wi-Fi MAC and ARP peers.
# Match Android common SELinux behavior; do not add any permissive allow rules.
python3 - "$K" <<'PY'
from pathlib import Path
import re,sys
k=Path(sys.argv[1])
c=k/"security/selinux/include/classmap.h"
s=c.read_text()
old='''\t{ "netlink_route_socket",
\t  { COMMON_SOCK_PERMS,
\t    "nlmsg_read", "nlmsg_write", NULL } },'''
new='''\t{ "netlink_route_socket",
\t  { COMMON_SOCK_PERMS,
\t    "nlmsg_read", "nlmsg_write", "nlmsg_readpriv",
\t    "nlmsg_getneigh", NULL } },'''
assert s.count(old)==1, "SELinux classmap route socket unexpected"
c.write_text(s.replace(old,new,1))

f=k/"security/selinux/nlmsgtab.c"
s=f.read_text()
for typ,permission in [
    ("RTM_GETLINK","NETLINK_ROUTE_SOCKET__NLMSG_READPRIV"),
    ("RTM_GETNEIGH","NETLINK_ROUTE_SOCKET__NLMSG_GETNEIGH"),
    ("RTM_GETNEIGHTBL","NETLINK_ROUTE_SOCKET__NLMSG_GETNEIGH"),
]:
    rx=r"(^[ \t]*\{[ \t]*"+typ+r",[ \t]*)NETLINK_ROUTE_SOCKET__NLMSG_READ([ \t]*\},)"
    s,n=re.subn(rx,lambda m:m.group(1)+permission+m.group(2),s,flags=re.M)
    assert n==1,f"Expected exactly one stock mapping for {typ}, got {n}"
f.write_text(s)
print("[+] SELinux Netlink: GETLINK->READPRIV, GETNEIGH/GETNEIGHTBL->GETNEIGH")
PY


grep -q 'SUSFS_VERSION "v2.3.0"' "$K/include/linux/susfs.h"

# Built-in NoMount is required for legacy 4.9: GKI LKMs included in module
# target only 5.10+ and the user's module requires NoMount kernel API v22+.
NM_SOURCE="$WORK/NoMount/kernel/src"
test ! -e "$K/fs/nomount"
grep -q '^#define NOMOUNT_BASE_VERSION "22"' "$NM_SOURCE/nomount.h"
ln -s ../../NoMount/kernel/src "$K/fs/nomount"
printf '\nobj-$(CONFIG_NOMOUNT) += nomount/\n' >> "$K/fs/Makefile"
python3 - "$K/fs/Kconfig" <<'PY'
from pathlib import Path
import sys
f=Path(sys.argv[1]); data=f.read_text()
anchor="\nendmenu\n"
assert data.count(anchor)>=1
at=data.rfind(anchor)
f.write_text(data[:at]+'\nsource "fs/nomount/Kconfig"\n'+data[at:])
PY

# ZeroTwo /proc/config.gz currently exposes vince-stock_defconfig instead of
# the actual build config; ReSuSFS mistakes built-in SUSFS for a missing LKM.
# Expose truthful config so built-in SUSFS detection succeeds.
python3 - "$K/kernel/Makefile" <<'PY'
from pathlib import Path
import sys
f=Path(sys.argv[1]); s=f.read_text()
before='$(obj)/config_data.gz: arch/arm64/configs/vince-stock_defconfig FORCE'
after='$(obj)/config_data.gz: $(KCONFIG_CONFIG) FORCE'
assert s.count(before)==1, 'Unexpected kernel/Makefile rule'
f.write_text(s.replace(before,after,1))
PY

# Preserve all original hardware settings and remove only stale KSU options.
python3 - "$K/arch/arm64/configs/vince-perf_defconfig" <<'PY'
from pathlib import Path
import re,sys
f=Path(sys.argv[1]); s=f.read_text()
assert "CONFIG_THREAD_INFO_IN_TASK=y" in s
s='\n'.join(l for l in s.splitlines()
 if not re.match(r'^(?:# )?CONFIG_KSU(?:_[A-Z0-9_]+)?(?:=| is not set)',l))+'\n'
s+="""
# vince SUSFS 2.3.0 with ReSukiSU inline SUSFS hook
CONFIG_KPROBES=y
CONFIG_DEBUG_KERNEL=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KSU=y
CONFIG_KSU_SUSFS=y
# CONFIG_KSU_MANUAL_HOOK is not set
CONFIG_KSU_MULTI_MANAGER_SUPPORT=y
# CONFIG_KPM is not set
CONFIG_KSU_SUSFS_SUS_PATH=y
CONFIG_KSU_SUSFS_SUS_MOUNT=y
CONFIG_KSU_SUSFS_SUS_KSTAT=y
CONFIG_KSU_SUSFS_SPOOF_UNAME=y
CONFIG_KSU_SUSFS_ENABLE_LOG=y
CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y
CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y
CONFIG_KSU_SUSFS_OPEN_REDIRECT=y
CONFIG_KSU_SUSFS_SUS_MAP=y
CONFIG_NOMOUNT=y
"""
f.write_text(s)
PY

cat > "$OUT/MANIFEST.txt" <<EOF
DEVICE=vince
BASE=ZeroTwo 4.9.337
KERNEL_SOURCE_COMMIT=$KERNEL
ROOT_IMPL=ReSukiSU
ROOT_COMMIT=$ROOT_SU
ROOT_MODE=KSU_SUSFS_INLINE_LINUX49
SUSFS_4_9_PORT_COMMIT=$SUSFS
ANYKERNEL_COMMIT=$ANYKERNEL
NOMOUNT_COMMIT=$NOMOUNT
NOMOUNT_KERNEL_API=22
SELINUX_NETLINK_HARDENING=READPRIV_GETNEIGH_ANDROID13
ROM_ADBROOT_POLICY_CHANGED=NO
SUSFS_VERSION=v2.3.0
DEVICE_BOOT_TESTED=NO
MODULE_INSTALL_TESTED=NO
NOTE=PRELIMINARY_COMPILE_ONLY_DEVICE_TEST_REQUIRED
EIGHT_MODULES_RUNTIME_TESTED=NO
EOF

cd "$K"
git diff --stat > "$OUT/kernel-changes.txt"
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
export CROSS_COMPILE_ARM32=arm-linux-gnueabi-
export CLANG_TRIPLE=aarch64-linux-gnu-
export KBUILD_BUILD_USER=VinceBuilder
export KBUILD_BUILD_HOST=GitHubActions
make O=out ARCH=arm64 vince-perf_defconfig
for sym in KSU KPROBES KALLSYMS_ALL KSU_SUSFS KSU_SUSFS_SUS_PATH KSU_SUSFS_SUS_MOUNT KSU_SUSFS_SUS_KSTAT KSU_SUSFS_SUS_MAP NOMOUNT IKCONFIG_PROC; do
 grep -qx "CONFIG_$sym=y" out/.config || { echo "Missing CONFIG_$sym=y" >&2; exit 1; }
done
! grep -q '^CONFIG_KSU_MANUAL_HOOK=y' out/.config
! grep -q '^CONFIG_KPM=y' out/.config
# ReSukiSU selects SUSFS hooks for old kernels without modern syscall dispatch.

# ReSukiSU's ksu.c includes generated/compile.h, which is normally created
# as a vmlinux/init-version dependency, not by make prepare. Produce this
# actual kernel-generated file before isolated object preflight.
# SELinux 4.9 generates its headers only when building security/selinux/.
# Prebuild this real target first; do not invent flask.h or bypass its ACLs.
echo "[+] Build SELinux 4.9 generated policy headers"
make -j2 O=out ARCH=arm64 CC=clang-14 CROSS_COMPILE="$CROSS_COMPILE" \
 CROSS_COMPILE_ARM32="$CROSS_COMPILE_ARM32" CLANG_TRIPLE="$CLANG_TRIPLE" \
 security/selinux/
test -s out/security/selinux/flask.h
test -s out/security/selinux/av_permissions.h

echo "[+] Generate native kernel compile.h for root preflight"
make O=out ARCH=arm64 CC=clang-14 CROSS_COMPILE="$CROSS_COMPILE" \
 CROSS_COMPILE_ARM32="$CROSS_COMPILE_ARM32" CLANG_TRIPLE="$CLANG_TRIPLE" \
 init/version.o
test -s out/include/generated/compile.h

echo "[+] Preflight ReSukiSU kernel objects (faster diagnosis)"
make -j2 O=out ARCH=arm64 CC=clang-14 CROSS_COMPILE="$CROSS_COMPILE" \
 CROSS_COMPILE_ARM32="$CROSS_COMPILE_ARM32" CLANG_TRIPLE="$CLANG_TRIPLE" drivers/kernelsu/

echo "[+] Compiling kernel"
make -j2 O=out ARCH=arm64 CC=clang-14 CROSS_COMPILE="$CROSS_COMPILE" \
 CROSS_COMPILE_ARM32="$CROSS_COMPILE_ARM32" CLANG_TRIPLE="$CLANG_TRIPLE" Image.gz-dtb

IMG="$K/out/arch/arm64/boot/Image.gz-dtb"
test -s "$IMG"
BYTES=$(stat -c %s "$IMG")
(( BYTES > 1048576 && BYTES < 104857600 ))
cp "$IMG" "$OUT/Image.gz-dtb"
sha256sum "$IMG" > "$OUT/kernel-sha256.txt"

get_source https://github.com/rahmatsobrian/AnyKernel3.git "$WORK/AnyKernel3" "$ANYKERNEL"
AK="$WORK/AnyKernel3"
grep -qx 'device.name1=vince' "$AK/anykernel.sh"
grep -qx 'BLOCK=/dev/block/bootdevice/by-name/boot;' "$AK/anykernel.sh"
find "$AK" -maxdepth 1 -type f -name 'Image*' -delete
cp "$IMG" "$AK/Image.gz-dtb"
cp "$OUT/MANIFEST.txt" "$AK/BUILD-MANIFEST.txt"
# Verify installation on the actual boot partition. Fail closed and preserve
# original boot image in RAM throughout this operation; never claim boot tested.
python3 - "$AK/anykernel.sh" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
content = path.read_text()
dump_anchor = "dump_boot; # use split_boot to skip ramdisk unpack, e.g. for devices with init_boot ramdisk\n"
write_anchor = "write_boot; # use flash_boot to skip ramdisk repack, e.g. for devices with init_boot ramdisk\n"
assert content.count("\n" + dump_anchor) == 1, "unexpected AnyKernel boot dump stanza"
assert content.count("\n" + write_anchor) == 1, "unexpected AnyKernel boot write stanza"
preflight = r'''
# InstallerFIX3: capture and validate original boot partition BEFORE writing.
ui_print "Checking original boot image and recovery backup...";
if [ ! -b "$BLOCK" ] || [ ! -s "$BOOTIMG" ]; then
  abort "Original boot backup or block device missing. No write attempted.";
fi;
boot_backup_size=$(wc -c < "$BOOTIMG");
if [ "$boot_backup_size" -lt 1048576 ]; then
  abort "Original boot image too small. No write attempted.";
fi;
boot_backup_magic=$(dd if="$BOOTIMG" bs=8 count=1 2>/dev/null);
if [ "$boot_backup_magic" != "ANDROID!" ]; then
  abort "Original boot does not have an Android boot header. No write attempted.";
fi;
boot_backup_sha256=$(sha256sum "$BOOTIMG" | cut -d' ' -f1);
if [ -z "$boot_backup_sha256" ]; then
  abort "Cannot verify original boot backup. No write attempted.";
fi;
ui_print "PASS: original boot backup checked. Keep an external boot backup.";
'''
verify = r'''
# Verify flash readback. If corrupt, attempt automatic restoration of the
# original complete boot partition from the validated dump.
ui_print "Verifying boot partition write on $BLOCK...";
if [ ! -s "$AKHOME/boot-new.img" ]; then
  abort "AnyKernel output missing; boot write NOT confirmed.";
fi;
if [ ! -b "$BLOCK" ]; then
  abort "Boot device not accessible as block device; write NOT confirmed.";
fi;
verify_size=$(wc -c < "$AKHOME/boot-new.img");
if [ "$verify_size" -lt 1048576 ] || [ "$verify_size" -gt "$boot_backup_size" ]; then
  abort "Unexpected repacked boot size. Installation NOT confirmed.";
fi;
verify_blocks=$(( (verify_size + 4095) / 4096 ));
verify_expected=$(sha256sum "$AKHOME/boot-new.img" | cut -d' ' -f1);
sync;
verify_actual=$(dd if="$BLOCK" bs=4096 count="$verify_blocks" 2>/dev/null | head -c "$verify_size" | sha256sum | cut -d' ' -f1);
if [ -z "$verify_actual" ] || [ "$verify_expected" != "$verify_actual" ]; then
  ui_print "BOOT READBACK MISMATCH. Trying to restore original boot...";
  if [ -s "$BOOTIMG" ] && [ "$(sha256sum "$BOOTIMG" | cut -d' ' -f1)" = "$boot_backup_sha256" ]; then
    if dd if="$BOOTIMG" of="$BLOCK" bs=4096 2>/dev/null; then
      sync;
      restore_blocks=$(( (boot_backup_size + 4095) / 4096 ));
      restore_actual=$(dd if="$BLOCK" bs=4096 count="$restore_blocks" 2>/dev/null | head -c "$boot_backup_size" | sha256sum | cut -d' ' -f1);
      if [ "$restore_actual" = "$boot_backup_sha256" ]; then
        abort "New kernel NOT installed. ORIGINAL boot restored and SHA-256 verified.";
      fi;
    fi;
  fi;
  abort "CRITICAL: boot readback failed AND original restoration was not verified. Stay in recovery; restore external boot backup.";
fi;
ui_print "PASS: written boot image matches (SHA-256).";
'''
content = content.replace(dump_anchor, dump_anchor + preflight + "\n", 1)
content = content.replace(write_anchor, write_anchor + verify + "\n", 1)
path.write_text(content)
PY
printf '\nINSTALLER_BOOT_READBACK_VERIFICATION=SHA256_WITH_PRECHECK_AND_RESTORE\nINSTALLER_FIXED_VERSION=3\n' >> "$AK/BUILD-MANIFEST.txt"
ZIP="$OUT/ZeroTwo-ReSukiSU-SUSFS230-NoMount22-vince-UNTESTED.zip"
(cd "$AK" && zip -qr9 "$ZIP" . -x '.git/*' '.git/**' '*.zip')
unzip -tq "$ZIP"
unzip -Z1 "$ZIP" | grep -qx "Image.gz-dtb"
unzip -Z1 "$ZIP" | grep -qx "anykernel.sh"
sha256sum "$ZIP" > "$OUT/zip-sha256.txt"
echo "[SUCCESS] Experimental ZIP built. NOT BOOT-VERIFIED; do not label as FINAL."
