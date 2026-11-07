#!/usr/bin/env python3
"""Verify V5 manager trust-key is compiled and appended DTB matches booted V4.

Static inspection only. Never present this as a boot, module or Android test.
"""
import argparse
import hashlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path

CUSTOM=b"b8eac4bd07e3cfee160808a6297cd59bae3878a66d233cfcaf383c3cc4e4395b"
EXISTING=b"d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64"

def load(path):
    if path.suffix==".zip":
        with zipfile.ZipFile(path) as z:
            if z.testzip(): raise ValueError("ZIP CRC failure")
            b=z.read("Image.gz-dtb")
    else: b=path.read_bytes()
    if b[:2]!=b"\x1f\x8b": raise ValueError("gzip image missing")
    decomp=zlib.decompressobj(16+zlib.MAX_WBITS)
    k=decomp.decompress(b)+decomp.flush()
    dtb=decomp.unused_data
    if dtb[:4]!=b"\xd0\x0d\xfe\xed": raise ValueError("DTB magic missing")
    if len(dtb)<8 or struct.unpack_from(">I",dtb,4)[0]>len(dtb):
        raise ValueError("invalid DTB size")
    return k,dtb

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("new",type=Path)
    p.add_argument("--baseline",type=Path)
    p.add_argument("--expect-custom",action="store_true")
    a=p.parse_args()
    try:
        kernel,dtb=load(a.new)
        print("kernel_size",len(kernel),"dtb_size",len(dtb))
        print("dtb_sha256",hashlib.sha256(dtb).hexdigest())
        print("existing_signer_present",EXISTING in kernel)
        print("custom_34606_signer_present",CUSTOM in kernel)
        if EXISTING not in kernel: raise ValueError("upstream signer missing")
        if a.expect_custom and CUSTOM not in kernel:
            raise ValueError("custom signer not compiled")
        if a.baseline:
            oldkernel,olddtb=load(a.baseline)
            if CUSTOM in oldkernel: raise ValueError("baseline already contains new signer")
            if olddtb!=dtb: raise ValueError("hardware DTB differs from booted V4")
            print("dtb_vs_v4=BYTE_IDENTICAL")
        print("PASS: STATIC IMAGE ONLY, NOT A DEVICE TEST")
        return 0
    except Exception as e:
        print("FAIL:",e,file=sys.stderr)
        return 2
if __name__=="__main__": sys.exit(main())
