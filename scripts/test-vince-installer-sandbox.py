#!/usr/bin/env python3
"""AnyKernel4 offline rollback unit tests: sandbox files, NOT phone flash."""
import os
import subprocess
import tempfile
from pathlib import Path

src = Path(__file__).parent / "build-vince-resukisu-susfs-experimental.sh"
text = src.read_text()
marker = 'python3 - "$AK/anykernel.sh" <<\'PY\'\n'
assert text.count(marker) == 1, "Installer generator not found"
generator = text.split(marker, 1)[1].split("\nPY\n", 1)[0]
dump_anchor = "dump_boot; # use split_boot to skip ramdisk unpack, e.g. for devices with init_boot ramdisk\n"
write_anchor = "write_boot; # use flash_boot to skip ramdisk repack, e.g. for devices with init_boot ramdisk\n"

with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    generated = base / "anykernel.sh"
    generated.write_text("#!/sbin/sh\n" + dump_anchor + "\n# init.rc\n# fstab.tuna\n" + write_anchor + "\n## end boot install\n")
    p = subprocess.run(["python3", "-", str(generated)], input=generator,
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    subprocess.run(["bash", "-n", str(generated)], check=True)
    result = generated.read_text()
    assert "if ( write_boot ); then" in result, "Write errors would bypass rollback"
    assert "restore_original_boot()" in result, "Restore function missing"
    assert result.count("write_boot") >= 1
    preflight = result.split(dump_anchor,1)[1].split("# init.rc",1)[0]
    verification = result.split("# fstab.tuna",1)[1].split("## end boot install",1)[0]
    body = """#!/bin/sh
ui_print() { echo "$*"; }
abort() { echo "$*"; exit 77; }
write_boot() {
  case "$SIM_WRITE_MODE" in
    ok) cp "$AKHOME/boot-new.img" "$BLOCK" ;;
    corrupt)
      cp "$AKHOME/boot-new.img" "$BLOCK";
      printf X | dd of="$BLOCK" bs=1 seek=8192 conv=notrunc 2>/dev/null
      ;;
    earlyabort)
      dd if="$AKHOME/boot-new.img" of="$BLOCK" bs=4096 count=1 2>/dev/null;
      abort "simulated AnyKernel early write failure"
      ;;
    no_image)
      cp "$AKHOME/boot-new.img" "$BLOCK";
      rm "$AKHOME/boot-new.img"
      ;;
    *) abort "unknown test write mode" ;;
  esac
}
"""
    mock = body + preflight + verification
    # ONLY mock files; the actual ZIP tests the physical block device via -b.
    mock = mock.replace('[ ! -b "$BLOCK" ]', '[ ! -f "$BLOCK" ]')
    generated.write_text(mock)
    subprocess.run(["bash", "-n", str(generated)], check=True)
    backup = b"ANDROID!" + os.urandom(2097152 - 8)
    image = b"ANDROID!" + os.urandom(2097152 - 8)
    cases = [
        ("correct_write", "ok", backup, backup, 0, False),
        ("corrupt_readback", "corrupt", backup, backup, 77, True),
        ("early_anykernel_abort", "earlyabort", backup, backup, 77, True),
        ("missing_repacked_image", "no_image", backup, backup, 77, True),
        ("invalid_android_header", "ok", b"INVALID!" + backup[8:], backup, 77, False),
        ("missing_original_backup", "ok", None, backup, 77, False),
        ("missing_partition", "ok", backup, None, 77, False),
    ]
    for name, mode, orig, part, expected_code, check_restore in cases:
        folder=base/name;folder.mkdir()
        if orig is not None:(folder/"boot.img").write_bytes(orig)
        if part is not None:(folder/"partition").write_bytes(part)
        (folder/"boot-new.img").write_bytes(image)
        env=dict(os.environ, AKHOME=str(folder),
                 BOOTIMG=str(folder/"boot.img"), BLOCK=str(folder/"partition"),
                 SIM_WRITE_MODE=mode)
        run=subprocess.run(["busybox","ash",str(generated)],env=env,
                           capture_output=True,text=True,timeout=30)
        assert run.returncode==expected_code, (name,run.returncode,run.stdout,run.stderr)
        if check_restore:
            assert (folder/"partition").read_bytes()==orig, ("restore mismatch",name)
            assert "restored and verified" in run.stdout, (name,run.stdout)
        elif part is not None:
            assert (folder/"partition").read_bytes()==part, (name,"unexpected write")
        print(f"PASS: {name} (exit={run.returncode})")
    print("PASS: 7/7 isolated AnyKernel4 checks (no actual recovery/Android used).")
