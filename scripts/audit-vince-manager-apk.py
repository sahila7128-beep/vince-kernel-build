#!/usr/bin/env python3
"""Read-only APK signing certificate vs pinned ReSukiSU trust-list audit."""
import argparse
import hashlib
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

def part(buf, p=0):
    if p+4 > len(buf): raise ValueError("truncated field")
    n=struct.unpack_from("<I",buf,p)[0]
    if n > len(buf)-p-4: raise ValueError("bad length")
    return buf[p+4:p+4+n],p+4+n

def certificates(apk):
    data=apk.read_bytes()
    with zipfile.ZipFile(apk) as z:
        if z.testzip(): raise ValueError("ZIP CRC failed")
    off=data.rfind(b"PK\x05\x06",max(0,len(data)-65557))
    if off < 0 or off+22 > len(data): raise ValueError("EOCD missing")
    if off+22+struct.unpack_from("<H",data,off+20)[0] != len(data):
        raise ValueError("unexpected ZIP comment")
    cd=struct.unpack_from("<I",data,off+16)[0]
    if cd<32 or cd>off or data[cd-16:cd]!=b"APK Sig Block 42":
        raise ValueError("APK Signing Block missing")
    size=struct.unpack_from("<Q",data,cd-24)[0]
    start=cd-size-8
    if start<0 or struct.unpack_from("<Q",data,start)[0]!=size:
        raise ValueError("invalid signing block framing")
    pos=start+8
    certs=set()
    while pos<cd-24:
        if pos+12>cd-24: raise ValueError("truncated signing entry")
        n=struct.unpack_from("<Q",data,pos)[0]
        ident=struct.unpack_from("<I",data,pos+8)[0]
        if n<4 or pos+8+n>cd-24: raise ValueError("invalid signing entry")
        if ident in (0x7109871a,0xf05368c0,0x1b93ad61):
            signers,_=part(data[pos+12:pos+8+n])
            s=0
            while s<len(signers):
                signer,s=part(signers,s)
                signed,_=part(signer)
                _,t=part(signed)
                series,_=part(signed,t)
                k=0
                while k<len(series):
                    cert,k=part(series,k)
                    certs.add((len(cert),hashlib.sha256(cert).hexdigest()))
        pos+=8+n
    if pos!=cd-24 or not certs: raise ValueError("certificate not found")
    return sorted(certs)

def kernel_trust(header):
    data=header.read_text(encoding="utf-8")
    sizes=dict(re.findall(r"^#define\s+EXPECTED_SIZE_(\w+)\s+(0x[0-9a-fA-F]+|\d+)",data,re.M))
    ret={}
    for name,size in sizes.items():
        pat=r'^#define\s+EXPECTED_HASH_'+re.escape(name)+r'\s*\\?\s*\n\s*"([0-9a-fA-F]{64})"'
        m=re.search(pat,data,re.M)
        if m: ret[name]=(int(size,0),m.group(1).lower())
    custom_size=re.search(r"^#define\s+EXPECTED_SIZE\s+(0x[0-9a-fA-F]+|\d+)",data,re.M)
    custom_hash=re.search(r'^#define\s+EXPECTED_HASH\s*\\?\s*\n\s*"([0-9a-fA-F]{64})"',data,re.M)
    if custom_size and custom_hash:
        ret["VINCE_CUSTOM"]=(int(custom_size.group(1),0),custom_hash.group(1).lower())
    if "RESUKISU" not in ret: raise ValueError("unknown trust-list format")
    return ret

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk",type=Path,required=True)
    p.add_argument("--manager-sign-header",type=Path,required=True)
    p.add_argument("--output",type=Path)
    a=p.parse_args()
    try:
        seen=certificates(a.apk); expected=kernel_trust(a.manager_sign_header)
        matched=sorted(n for n,v in expected.items() if n!="OTHER" and v in seen)
        result={"apk_sha256":hashlib.sha256(a.apk.read_bytes()).hexdigest(),
                "certificates":[{"der_size":s,"sha256":h} for s,h in seen],
                "trusted_key_names":matched,"kernel_static_allowlist_match":bool(matched),
                "apk_signature_crypto_verified":False,
                "manager_kernel_uapi_runtime_tested":False,
                "modules_runtime_tested":False,
                "verdict":"STATIC_MATCH_ONLY" if matched else "NOT_TRUSTED_BY_PINNED_KERNEL"}
        data=json.dumps(result,indent=2)+"\n"
        print(data)
        if a.output: a.output.write_text(data)
        return 0 if matched else 2
    except Exception as exc:
        print("[INVALID] "+str(exc),file=sys.stderr); return 3

if __name__=="__main__": sys.exit(main())
