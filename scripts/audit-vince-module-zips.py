#!/usr/bin/env python3
"""Read-only static checks of KernelSU module ZIPs for vince/Android 13.

This script NEVER executes an install script and cannot prove Android runtime support.
Run: python3 scripts/audit-vince-module-zips.py /path/to/your/module-zip-directory
"""
import argparse
import io
import json
import re
import sys
import zipfile
from pathlib import Path

PATTERNS = {
    "DIRTY_SYSTEM_SERVER_EXECMEM": r"(?m)^\s*allow\s+system_server\s+system_server\s+process\s+(?:execmem|\{[^}]*\bexecmem\b[^}]*\})",
    "DIRTY_ADBROOT_TYPE": r"\btype\s+adbroot\s+domain\b",
    "DIRTY_ZYGOTE_ADB_DATA": r"\ballow\s+zygote\s+adb_data_file\s+dir\s+search\b",
    "BROAD_ZYGOTE_RULE": r"\ballow\s+\*\s+zygote\s+unix_stream_socket\b",
}

def scan_zip(path):
    result = {"zip":path.name, "crc":"FAIL", "id":"unknown", "findings":[]}
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        if any(x.startswith("/") or ".." in Path(x).parts for x in names):
            result["error"] = "unsafe path in ZIP"; return result
        bad = z.testzip()
        if bad:
            result["error"] = "CRC: " + bad; return result
        result["crc"]="PASS"
        def read(name):
            if name not in names: return ""
            info = z.getinfo(name)
            if info.file_size > 1024 * 1024: return ""
            return z.read(name).decode("utf8","replace")
        prop = read("module.prop")
        m = re.search(r"(?m)^id=([^\r\n]+)",prop)
        if m:result["id"]=m.group(1).strip()
        for filename in ("sepolicy.rule","customize.sh","install.sh","post-fs-data.sh","service.sh"):
            source = read(filename)
            for code, pattern in PATTERNS.items():
                for m in list(re.finditer(pattern,source,re.I))[:3]:
                    result["findings"].append({
                      "code":code,"file":filename,"line":source.count("\n",0,m.start())+1})
        if result["id"]=="small_module" and "ksud sepolicy apply" in read("customize.sh"):
            result["findings"].append({"code":"DIRECT_POLICY_MUTATION","file":"customize.sh"})
        if result["id"]=="fgetpriority" and not any(
            p.startswith("ko/") and p.endswith(".ko") and "4.9" in p for p in names):
            result["findings"].append({"code":"NO_KERNEL49_DRIVER","file":"ko/"})
        if result["id"]=="nomount":
            result["findings"].append({"code":"REQUIRES_NOMOUNT_API22","file":"module.prop"})
    return result

def scan(paths):
    items = []
    for path in paths:
        try: items.append(scan_zip(path))
        except (zipfile.BadZipFile,OSError) as e:
            items.append({"zip":path.name,"crc":"FAIL","error":str(e),"id":"unknown","findings":[]})
    ids = {x["id"] for x in items}
    conflicts = []
    if {"ReSuSFS","brene"} <= ids:
        conflicts.append("Both ReSuSFS and BRENE manage SUSFS; avoid enabling both without live conflict test.")
    if {"rezygisk","treat_wheel"} <= ids:
        conflicts.append("BreWheel requires a compatible ReZygisk version; installer must validate it.")
    return {
      "device":"vince", "source_only":True, "kernel_build":"ReSukiSU SUSFS 2.3.0 NoMount v22 research",
      "live_dirtysepolicy_verified":False,"banking_tested":False,
      "install_runtime_tested":False,
      "module_count":len(items),"modules":items,"conflicts":conflicts,
    }

def self_test():
    def sample(name, prop, rule="", custom=""):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,"w") as z:
            z.writestr("module.prop","id="+prop+"\n")
            if rule:z.writestr("sepolicy.rule",rule)
            if custom:z.writestr("customize.sh",custom)
        with zipfile.ZipFile(buf) as z:
            assert z.testzip() is None
        return buf
    a = sample("b","rezygisk","allow system_server system_server process execmem\nallow zygote adb_data_file dir search\n")
    b = sample("s","small_module","","echo 'type adbroot domain'\nksud sepolicy apply rule\n")
    # Scan in-memory ZIPs using a bounded temporary fixture directory.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in (("b.zip",a),("s.zip",b)):
            (Path(tmp)/name).write_bytes(data.getvalue())
        r = scan(sorted(Path(tmp).glob("*.zip")))
        found = {v["code"] for x in r["modules"] for v in x["findings"]}
        expected = {"DIRTY_SYSTEM_SERVER_EXECMEM","DIRTY_ZYGOTE_ADB_DATA",
                    "DIRTY_ADBROOT_TYPE","DIRECT_POLICY_MUTATION"}
        assert expected <= found, (expected, found)
    print("PASS: synthetic module policy detection tests (NOT physical installs).")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory",nargs="?",type=Path)
    p.add_argument("--output",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    if a.self_test:
        self_test();return 0
    if a.directory is None or not a.directory.is_dir():
        p.error("pass an existing directory containing user-supplied ZIPs")
    result=scan(sorted(a.directory.glob("*.zip")))
    data=json.dumps(result,indent=2,ensure_ascii=False)+"\n"
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(data)
    print(data)
    return 0

if __name__=="__main__":
    sys.exit(main())
