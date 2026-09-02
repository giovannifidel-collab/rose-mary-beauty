#!/usr/bin/env python3
"""Create/open authenticated encrypted Rose&Mary Beauty CI source bundles.

The public repository stores only authenticated ciphertext. The 32-byte AES key
is supplied at runtime through PFARMA_CI_BUNDLE_KEY and must never be committed.
Compatible with the existing PFARMA_CI_BUNDLE_V2 format.
"""
from __future__ import annotations
import argparse, base64, hashlib, io, json, os, tarfile
from pathlib import Path, PurePosixPath
from typing import Iterable
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC='PFARMA_CI_BUNDLE_V2'
ALGORITHM='AES-256-GCM'
DEFAULT_EXCLUDES={'.git','.env','.env.local','.env.production','.env.development','.venv','venv','node_modules','.next','__pycache__','.pytest_cache','dist','.wrangler'}
SENSITIVE_SUFFIXES=('.pem','.key','.p12','.pfx','.jks','.keystore')

def _load_key()->bytes:
    raw=os.environ.get('PFARMA_CI_BUNDLE_KEY','').strip()
    if not raw: raise SystemExit('PFARMA_CI_BUNDLE_KEY is required (base64-encoded 32-byte key).')
    try: key=base64.b64decode(raw,validate=True)
    except Exception as exc: raise SystemExit('PFARMA_CI_BUNDLE_KEY must be valid base64.') from exc
    if len(key)!=32: raise SystemExit('PFARMA_CI_BUNDLE_KEY must decode to exactly 32 bytes.')
    return key

def _aad(meta:dict[str,object])->bytes:
    return json.dumps(meta,sort_keys=True,separators=(',',':')).encode()

def _excluded(rel:PurePosixPath,extra:set[str])->bool:
    if set(rel.parts)&(DEFAULT_EXCLUDES|extra): return True
    name=rel.name.lower()
    if name.startswith('.env'): return True
    if name.endswith(SENSITIVE_SUFFIXES): return True
    if name in {'.npmrc','.pypirc'}: return True
    return False

def _files(root:Path,extra:set[str])->Iterable[tuple[Path,PurePosixPath]]:
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink(): continue
        rel=PurePosixPath(path.relative_to(root).as_posix())
        if not _excluded(rel,extra): yield path,rel

def pack(source:Path,output:Path,source_ref:str,extra:set[str])->None:
    source=source.resolve()
    if not source.is_dir(): raise SystemExit(f'Source directory does not exist: {source}')
    buf=io.BytesIO(); count=0
    with tarfile.open(fileobj=buf,mode='w:gz',format=tarfile.PAX_FORMAT) as arc:
        for path,rel in _files(source,extra):
            info=arc.gettarinfo(str(path),arcname=rel.as_posix()); info.uid=info.gid=0; info.uname=info.gname=''
            with path.open('rb') as fh: arc.addfile(info,fh)
            count+=1
    if count==0: raise SystemExit('No source files selected for the CI bundle.')
    plain=buf.getvalue(); digest=hashlib.sha256(plain).hexdigest()
    meta={'format':MAGIC,'algorithm':ALGORITHM,'source_ref':source_ref,'file_count':count,'plaintext_sha256':digest}
    nonce=os.urandom(12); ciphertext=AESGCM(_load_key()).encrypt(nonce,plain,_aad(meta))
    payload={**meta,'nonce_b64':base64.b64encode(nonce).decode(),'ciphertext_b64':base64.b64encode(ciphertext).decode()}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(payload,sort_keys=True,separators=(',',':')),encoding='utf-8')
    print(f'packed {count} files -> {output}')

def _safe_extract(arc:tarfile.TarFile,dest:Path)->None:
    dest=dest.resolve(); members=arc.getmembers()
    for m in members:
        p=(dest/m.name).resolve()
        if dest!=p and dest not in p.parents: raise SystemExit(f'Unsafe archive path rejected: {m.name}')
        if m.issym() or m.islnk() or m.isdev(): raise SystemExit(f'Unsupported archive member rejected: {m.name}')
    arc.extractall(dest,members=members,filter='data')

def unpack(bundle:Path,destination:Path)->None:
    try: payload=json.loads(bundle.read_text(encoding='utf-8'))
    except Exception as exc: raise SystemExit('Bundle is unreadable or invalid JSON.') from exc
    required={'format','algorithm','source_ref','file_count','plaintext_sha256','nonce_b64','ciphertext_b64'}
    if not isinstance(payload,dict) or set(payload)!=required: raise SystemExit('Bundle schema mismatch.')
    if payload['format']!=MAGIC or payload['algorithm']!=ALGORITHM: raise SystemExit('Unsupported bundle format or algorithm.')
    meta={k:payload[k] for k in ('format','algorithm','source_ref','file_count','plaintext_sha256')}
    try:
        nonce=base64.b64decode(payload['nonce_b64'],validate=True); ciphertext=base64.b64decode(payload['ciphertext_b64'],validate=True)
        if len(nonce)!=12: raise ValueError('invalid nonce')
        plain=AESGCM(_load_key()).decrypt(nonce,ciphertext,_aad(meta))
    except Exception as exc: raise SystemExit('Bundle authentication/decryption failed.') from exc
    if hashlib.sha256(plain).hexdigest()!=payload['plaintext_sha256']: raise SystemExit('Bundle plaintext checksum mismatch.')
    destination.mkdir(parents=True,exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz') as arc: _safe_extract(arc,destination)
    count=sum(1 for p in destination.rglob('*') if p.is_file())
    if count!=payload['file_count']: raise SystemExit('Extracted file count does not match authenticated metadata.')
    print(f'unpacked {count} files (source_ref={payload["source_ref"]})')

def main()->None:
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('pack'); p.add_argument('--source',type=Path,required=True); p.add_argument('--output',type=Path,required=True); p.add_argument('--source-ref',required=True); p.add_argument('--exclude',action='append',default=[])
    u=sub.add_parser('unpack'); u.add_argument('--bundle',type=Path,required=True); u.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='pack': pack(args.source,args.output,args.source_ref,set(args.exclude))
    else: unpack(args.bundle,args.destination)
if __name__=='__main__': main()
