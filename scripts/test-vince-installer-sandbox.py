#!/usr/bin/env python3
"""Test AnyKernel v3 safety logic using sandbox files (NOT physical recovery)."""
import os
import subprocess
import tempfile
from pathlib import Path

SRC = Path(__file__).parent / "build-vince-resukisu-susfs-experimental.sh"
source = SRC.read_text()
marker = 'python3 - "$AK/anykernel.sh" <<\'PY\'\n'
assert source.count(marker) == 1, "Missing exact AnyKernel generator"
code = source.split(marker, 1)[1].split("\nPY\n", 1)[0]
dump_anchor = "dump_boot; # use split_boot to skip ramdisk unpack, e.g. for devices with init_boot ramdisk\n"
write_anchor = "write_boot; # use flash_boot to skip ramdisk repack, e.g. for devices with init_boot ramdisk\n"

with tempfile.TemporaryDirectory() as directory:
    base = Path(directory)
    installer = base / "anykernel.sh"
    installer.write_text("#!/sbin/sh\n" + dump_anchor + "\n# init.rc\n" + write_anchor + "\n## end boot install\n")
    result = subprocess.run(["python3", "-", str(installer)],
                            input=code, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    subprocess.run(["bash", "-n", str(installer)], check=True)
    generated = installer.read_text()
    assert "SHA256_WITH_PRECHECK_AND_RESTORE" not in generated  # Manifest only.
    assert "ORIGINAL boot restored" in generated
    assert "Android boot header" in generated
    preflight = generated.split(dump_anchor, 1)[1].split("# init.rc", 1)[0]
    verify = generated.split(write_anchor, 1)[1].split("## end boot install", 1)[0]
    script = '#!/bin/sh\nui_print(){ echo "$*"; }\nabort(){ echo "$*"; exit 77; }\n' + preflight + verify
    # ONLY within the sandbox mock replace block-device type test with file test.
    script = script.replace('if [ ! -b "$BLOCK" ]', 'if [ ! -f "$BLOCK" ]')
    installer.write_text(script)
    subprocess.run(["bash", "-n", str(installer)], check=True)
    old = b"ANDROID!" + os.urandom(2 * 1024 * 1024 - 8)
    new = b"ANDROID!" + os.urandom(2 * 1024 * 1024 - 8)
    test_cases = [
        ("matching_flash", old, new, 0, False),
        ("corrupt_flash_auto_restore", old, new[:8000] + b"!" + new[8001:], 77, True),
        ("invalid_original_boot_header", b"BADBOOT!" + old[8:], new, 77, False),
        ("original_backup_missing", None, new, 77, False),
        ("boot_partition_missing", old, None, 77, False),
    ]
    for label, backup, device, expected_exit, expect_restore in test_cases:
        directory = base / label
        directory.mkdir()
        if backup is not None: (directory / "boot.img").write_bytes(backup)
        if device is not None: (directory / "partition").write_bytes(device)
        (directory / "boot-new.img").write_bytes(new)
        env = dict(os.environ, AKHOME=str(directory), BOOTIMG=str(directory / "boot.img"),
                   BLOCK=str(directory / "partition"))
        proc = subprocess.run(["busybox", "ash", str(installer)], env=env,
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == expected_exit, (label, proc.returncode, proc.stdout, proc.stderr)
        if expect_restore:
            assert (directory / "partition").read_bytes() == old, label
        elif device is not None:
            assert (directory / "partition").read_bytes() == device, label
        print("PASS", label, "exit_code", proc.returncode)
    print("PASS: recovery safety unit tests against sandbox files. Physical boot NOT tested.")
