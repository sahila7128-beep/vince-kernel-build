#!/system/bin/sh
# Read-only diagnostics for Xiaomi vince Android 13.
# On PC: adb shell sh -s < scripts/vince-diagnose-readonly.sh
set -u
echo "=== VINCE READ ONLY ==="
printf "device="; getprop ro.product.device
printf "android="; getprop ro.build.version.release
printf "kernel="; uname -r
printf "selinux="; getenforce
if [ -r /sys/fs/selinux/enforce ]; then
  printf "enforcing_flag="; cat /sys/fs/selinux/enforce
fi
echo "--- shell ---"; id
echo "--- daemon ---"; ps -A 2>/dev/null | grep -E "[k]sud|[m]agiskd" || true
if ! command -v su >/dev/null 2>&1; then
  echo "su unavailable; do not conclude root is broken"; exit 0
fi
su -c 'id;
  echo "--- ksud ---";
  if [ -f /data/adb/ksud ]; then
    ls -lZ /data/adb/ksud;
    /data/adb/ksud --version 2>&1;
  else echo "ksud absent at /data/adb"; fi;
  echo "--- module records ---";
  if [ -d /data/adb/modules ]; then
    for m in /data/adb/modules/*; do
      [ -d "$m" ] || continue;
      echo "module_path=$m";
      [ ! -r "$m/module.prop" ] || grep -E "^(id|name|version)=" "$m/module.prop";
      [ ! -e "$m/disable" ] || echo "module_disabled=yes";
      [ ! -r "$m/sepolicy.rule" ] || grep -nE "adbroot|ksu_file|execmem|zygote.*adb_data_file" "$m/sepolicy.rule" || true;
    done;
  fi;
  echo "--- adbroot in module scripts ---";
  for f in /data/adb/modules/*/post-fs-data.sh /data/adb/modules/*/service.sh; do
    [ -r "$f" ] || continue;
    grep -nE "type[[:space:]]+adbroot|adb_root" "$f" 2>/dev/null && echo "source=$f";
  done;
  echo "--- contexts ---";
  ls -dZ /data/adb /data/adb/modules /data/adb/ksud 2>/dev/null || true' 2>&1
echo "Read-only scan completed; no policy, module or kernel writes."
