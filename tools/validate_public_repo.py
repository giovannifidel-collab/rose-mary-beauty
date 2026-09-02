#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path, PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
ALLOWED_EXACT={
 PurePosixPath('README.md'),PurePosixPath('SECURITY.md'),PurePosixPath('.gitignore'),
 PurePosixPath('bundle/README.md'),PurePosixPath('bundle/rose-mary-beauty.bundle.json'),
 PurePosixPath('tools/public_ci_bundle.py'),PurePosixPath('tools/test_public_ci_bundle.py'),PurePosixPath('tools/validate_public_repo.py'),
 PurePosixPath('.github/workflows/bootstrap.yml'),PurePosixPath('.github/workflows/deploy-cloudflare.yml')}
REQ={'format','algorithm','source_ref','file_count','plaintext_sha256','nonce_b64','ciphertext_b64'}
def main():
    files=[]
    for p in ROOT.rglob('*'):
        if p.is_file() and '.git' not in p.relative_to(ROOT).parts: files.append(PurePosixPath(p.relative_to(ROOT).as_posix()))
    bad=sorted(str(x) for x in files if x not in ALLOWED_EXACT)
    if bad: raise SystemExit('Unexpected public-repository files rejected: '+', '.join(bad))
    b=ROOT/'bundle/rose-mary-beauty.bundle.json'; payload=json.loads(b.read_text())
    if set(payload)!=REQ or payload.get('format')!='PFARMA_CI_BUNDLE_V2' or payload.get('algorithm')!='AES-256-GCM': raise SystemExit('Encrypted bundle policy mismatch.')
    if not payload.get('ciphertext_b64'): raise SystemExit('Encrypted bundle has no ciphertext.')
    print(f'PASS: public boundary contains {len(files)} allowlisted files only.')
if __name__=='__main__': main()
