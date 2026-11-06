#!/usr/bin/env bash
# FinaSU Linux4.9 compile feasibility probe; NOT a validated boot kernel.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/work"
OUT="$ROOT/artifacts"
mkdir -p "$WORK" "$OUT"
trap 'echo "[FAILED] Inspect build log at line $LINENO" >&2' ERR

# Pinned sources -- reproducible and no moving main branch.
KERNEL=609a588f30d61a7f04e2061ab59c4f9c8c49aa6d
FINA=a839ce2d742f0f1450a3aad20bdc14bc060da840
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
get_source https://github.com/LyraVoid/FinaSU.git "$WORK/FinaSU" "$FINA"
get_source https://github.com/wxx9248/susfs4ksu.git "$WORK/susfs4ksu" "$SUSFS"
get_source https://github.com/maxsteeel/nomount.git "$WORK/NoMount" "$NOMOUNT"
K="$WORK/ZeroTwo"
P="$WORK/susfs4ksu/kernel_patches"

# Use exactly one KernelSU implementation.
test ! -e "$K/drivers/kernelsu"
ln -s ../../FinaSU/kernel "$K/drivers/kernelsu"
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

# Strict, version-pinned FinaSU compile compatibility adapters.
# This is NOT proof of a safe 4.9 arm64 syscall ABI for runtime root.
python3 "$ROOT/scripts/finasu_49_compile_adapter.py" "$K"

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


# Check SELinux symbol linkage for old 4.9 builds
# to have global linkage on old kernels. Never disable that build check.
python3 - "$K" <<'PY'
from pathlib import Path
import sys
k = Path(sys.argv[1])
symbols = {
    "security/selinux/selinuxfs.c": [
        ("static ssize_t (*write_op[])", "ssize_t (*write_op[])"),
        ("static const struct file_operations sel_handle_status_ops",
         "const struct file_operations sel_handle_status_ops"),
        ("static DEFINE_MUTEX(sel_mutex);", "DEFINE_MUTEX(sel_mutex);"),
    ],
    "security/selinux/ss/status.c": [
        ("static struct page *selinux_status_page;", "struct page *selinux_status_page;"),
        ("static DEFINE_MUTEX(selinux_status_lock);", "DEFINE_MUTEX(selinux_status_lock);"),
    ],
    "security/selinux/ss/services.c": [
        ("static DEFINE_RWLOCK(policy_rwlock);", "DEFINE_RWLOCK(policy_rwlock);"),
    ],
}
for name, replacements in symbols.items():
    target = k / name
    data = target.read_text()
    for before, after in replacements:
        count = data.count(before)
        if count != 1:
            raise SystemExit(f"Static export: {name} expected one {before!r}, got {count}")
        data = data.replace(before, after, 1)
    target.write_text(data)
    print(f"[+] BakaSU SELinux symbol linkage corrected: {name}")
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
# vince SUSFS 2.3.0 with FinaSU tracepoint compile experiment
CONFIG_KPROBES=y
CONFIG_DEBUG_KERNEL=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KSU=y
CONFIG_KSU_HOOK_TRACEPOINT=y
# CONFIG_KSU_HOOK_SUSFS_INLINE is not set
CONFIG_KSU_SUSFS=y
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
FINASU_VERSION=v1.4.5
FINASU_COMMIT=$FINA
FINASU_BUILD_MODE=TRACEPOINT_EXPERIMENTAL_LINUX49
FINASU_PREINIT_REQUIRED=YES
SUSFS_4_9_PORT_COMMIT=$SUSFS
ANYKERNEL_COMMIT=$ANYKERNEL
NOMOUNT_COMMIT=$NOMOUNT
NOMOUNT_KERNEL_API=22
SELINUX_NETLINK_HARDENING=READPRIV_GETNEIGH_ANDROID13
ROM_ADBROOT_POLICY_CHANGED=NO
SUSFS_VERSION=v2.3.0
DEVICE_BOOT_TESTED=NO
MODULE_INSTALL_TESTED=NO
NOTE=EXPERIMENTAL_OUT_OF_SUPPORT_LINUX49
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
for sym in KSU KSU_HOOK_TRACEPOINT KPROBES KALLSYMS_ALL KSU_SUSFS KSU_SUSFS_SUS_PATH KSU_SUSFS_SUS_MOUNT KSU_SUSFS_SUS_KSTAT KSU_SUSFS_SUS_MAP NOMOUNT IKCONFIG_PROC; do
 grep -qx "CONFIG_$sym=y" out/.config || { echo "Missing CONFIG_$sym=y" >&2; exit 1; }
done
! grep -q '^CONFIG_KSU_HOOK_SUSFS_INLINE=y' out/.config
# Inline backend requires Linux 4.9 SUSFS preinit hook sites not in port; do not bypass FinaSU checks.

# FinaSU preinit is mandatory for its userspace startup and module handling.
# The original compiler probe silently disabled it if UAPI headers were absent.
echo "[+] Generate UAPI headers required for FinaSU preinit runner"
make O=out ARCH=arm64 INSTALL_HDR_PATH="$K/out/usr" headers_install
test -s "$K/out/usr/include/linux/unistd.h" || {
 echo "FinaSU preinit prerequisite missing: out/usr/include/linux/unistd.h" >&2; exit 1;
}


echo "[+] Preflight FinaSU kernel objects (faster diagnosis)"
make -j2 O=out ARCH=arm64 KSU_REQUIRE_PREINIT=1 CC=clang-14 CROSS_COMPILE="$CROSS_COMPILE" \
 CROSS_COMPILE_ARM32="$CROSS_COMPILE_ARM32" CLANG_TRIPLE="$CLANG_TRIPLE" drivers/kernelsu/

echo "[+] Compiling kernel"
make -j2 O=out ARCH=arm64 KSU_REQUIRE_PREINIT=1 CC=clang-14 CROSS_COMPILE="$CROSS_COMPILE" \
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
# Verify installation success on real boot partition rather than trusting
# legacy AnyKernel's write status (it may swallow write errors).
python3 - "$AK/anykernel.sh" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); content=path.read_text()
anchor="write_boot; # use flash_boot to skip ramdisk repack, e.g. for devices with init_boot ramdisk\n"
assert content.count("\n"+anchor)==1, "unexpected AnyKernel boot install stanza"
verify='''
# InstallerFIX2: AnyKernel3 creates boot-new.img under $AKHOME,
# not $SPLITIMG. Verify the written image-sized prefix of the partition.
ui_print "Verifying boot partition write on $BLOCK...";
if [ ! -s "$AKHOME/boot-new.img" ]; then
  abort "AnyKernel output missing: $AKHOME/boot-new.img; boot write NOT confirmed.";
fi;
if [ ! -b "$BLOCK" ]; then
  abort "Boot device not accessible as block device; write NOT confirmed.";
fi;
verify_size=$(wc -c < "$AKHOME/boot-new.img");
if [ "$verify_size" -lt 1048576 ]; then
  abort "Unexpectedly small repacked boot image. Installation NOT confirmed.";
fi;
verify_blocks=$(( (verify_size + 4095) / 4096 ));
verify_expected=$(sha256sum "$AKHOME/boot-new.img" | cut -d' ' -f1);
sync;
verify_actual=$(dd if="$BLOCK" bs=4096 count="$verify_blocks" 2>/dev/null | head -c "$verify_size" | sha256sum | cut -d' ' -f1);
if [ -z "$verify_actual" ] || [ "$verify_expected" != "$verify_actual" ]; then
  abort "BOOT READBACK MISMATCH: partition does not match image. Restore boot backup before reboot.";
fi;
ui_print "PASS: written boot image matches (SHA-256).";
'''
path.write_text(content.replace(anchor,anchor+verify+"\n",1))
PY
printf '\nINSTALLER_BOOT_READBACK_VERIFICATION=SHA256_ACTUAL_AKHOME_PATH\nINSTALLER_FIXED_VERSION=2\n' >> "$AK/BUILD-MANIFEST.txt"
ZIP="$OUT/ZeroTwo-FinaSU145-SUSFS230-NoMount22-vince-UNTESTED.zip"
(cd "$AK" && zip -qr9 "$ZIP" . -x '.git/*' '.git/**' '*.zip')
unzip -tq "$ZIP"
unzip -Z1 "$ZIP" | grep -qx "Image.gz-dtb"
unzip -Z1 "$ZIP" | grep -qx "anykernel.sh"
sha256sum "$ZIP" > "$OUT/zip-sha256.txt"
echo "[SUCCESS] Experimental kernel ZIP compiled; boot/device not tested."
