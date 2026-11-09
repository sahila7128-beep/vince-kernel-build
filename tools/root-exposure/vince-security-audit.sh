#!/system/bin/sh
# VINCE ROOT EXPOSURE AUDIT — READ ONLY
# This inspects the owner's Android environment; it makes NO changes.
# Designed for Vince-C12-RC3, FinaSU and AlwaysStrong PR76.
# It does NOT establish whether any bank will accept or reject a login.
PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin:$PATH
export PATH
umask 077

say() { printf '%s\n' "$1"; }
field() { printf '%-31s : %s\n' "$1" "$2"; }
prop() {
    _k="$1"
    _v="$(getprop "$_k" 2>/dev/null)"
    if [ -n "$_v" ]; then
        case "$_k" in
            persist.sys.pixelprops.gms|persist.sys.pixelprops.gphotos|persist.sys.pixelprops.*|persist.sys.certifiedKeybox|config_certifiedKeybox)
                field "$_k" "PRESENT (value suppressed)"
                ;;
            *) field "$_k" "$_v" ;;
        esac
    else
        field "$_k" "NOT_SET_OR_EMPTY"
    fi
}
package_present() {
    _p="$1"
    if pm list packages "$_p" 2>/dev/null | grep -Fxq "package:$_p"; then
        field "$_p" "INSTALLED"
    else
        field "$_p" "NOT_FOUND_BY_PM"
    fi
}

say '=== VINCE READ-ONLY ROOT EXPOSURE AUDIT ==='
field "Date on device" "$(date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null)"
field "Android release" "$(getprop ro.build.version.release)"
field "Kernel release" "$(uname -r)"
field "Shell UID" "$(id -u)"
field "SELinux" "$(getenforce 2>/dev/null || echo UNKNOWN)"
say 'Important: claimed boot properties below can be altered by root/modules.'
prop ro.build.type
prop ro.debuggable
prop ro.secure
prop ro.boot.flash.locked
prop ro.boot.vbmeta.device_state
prop ro.boot.verifiedbootstate

say ''
say '=== KNOWN ROOT/HOOK MANAGER APP PACKAGES ==='
package_present me.yuki.fina
package_present org.frknkrc44.hma_oss
package_present com.tsng.hidemyapplist

say ''
say '=== MODIFICATION PROPERTY PRESENCE (NOT CONTENTS) ==='
prop persist.sys.pixelprops.gms
prop persist.sys.pixelprops.gphotos
prop config_certifiedKeybox

say ''
say '=== INSTALLED MODULE INVENTORY (IDS ONLY; NO PRIVATE CONFIG FILES) ==='
_dir=/data/adb/modules
if [ -d "$_dir" ] && [ -r "$_dir" ]; then
    _count=0
    for _m in "$_dir"/*; do
        [ -d "$_m" ] || continue
        [ -f "$_m/module.prop" ] || continue
        _count=$((_count + 1))
        _id="$(sed -n 's/^id=//p' "$_m/module.prop" 2>/dev/null | head -n 1)"
        [ -n "$_id" ] || _id="$(basename "$_m")"
        _state=ACTIVE
        [ -f "$_m/disable" ] && _state=DISABLED
        [ -f "$_m/remove" ] && _state=PENDING_REMOVAL
        _rules=NO
        [ -s "$_m/sepolicy.rule" ] && _rules=YES
        _props=NO
        [ -s "$_m/system.prop" ] && _props=YES
        _zygisk=NO
        [ -d "$_m/zygisk" ] && _zygisk=YES
        printf 'MODULE %-32s state=%-16s sepolicy=%-3s system.prop=%-3s zygisk=%s\n' "$_id" "$_state" "$_rules" "$_props" "$_zygisk"
    done
    field "Module count" "$_count"
else
    say 'Module directory not accessible (run from adb shell with authorized su).'
fi

say ''
say '=== TEESIMULATOR DEX BUILD CHECK (DIGEST ONLY) ==='
_dex=/data/adb/modules/tricky_store/tee_classes.dex
if [ -r "$_dex" ]; then
    _digest="$(sha256sum "$_dex" 2>/dev/null | cut -d' ' -f1)"
    field "Actual tee_classes.dex SHA256" "$_digest"
    if [ "$_digest" = '453744e949d8bd9013a76916c2579004e73ec0eddf59cacd9a62f29ea9271d7c' ]; then
        say 'DEX: matches prior source-built PR76 DEX-only trial.'
    else
        say 'DEX: DIFFERENT / not identifiable from expected PR76 digest.'
    fi
else
    say 'DEX: unavailable; cannot verify active Inject code by hash.'
fi

say ''
say '=== AUDIT CONSTRAINTS ==='
say 'No shell commands modified packages, apps, keys, SELinux or kernel.'
say 'No keybox XML, PINs, bank/app identifiers, user serials, or private keys were read.'
say 'Rooted/modified OS remains a possible bank risk, even if a test app displays green.'
say 'Do not use this tool as proof that an app is safe to log in or pay with.'
