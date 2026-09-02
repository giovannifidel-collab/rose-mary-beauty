from __future__ import annotations
import base64, json, os, subprocess, sys, tempfile
from pathlib import Path
SCRIPT=Path(__file__).with_name('public_ci_bundle.py')
def run(*args:str,env:dict[str,str]):
    return subprocess.run([sys.executable,str(SCRIPT),*args],text=True,capture_output=True,env=env,check=False)
def main():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); source=root/'source'; source.mkdir(); (source/'app.txt').write_text('Rose&Mary secret source\n'); (source/'.env').write_text('NO=LEAK\n')
        key=base64.b64encode(os.urandom(32)).decode(); env=os.environ.copy(); env['PFARMA_CI_BUNDLE_KEY']=key
        bundle=root/'bundle.json'; r=run('pack','--source',str(source),'--output',str(bundle),'--source-ref','test-ref',env=env); assert r.returncode==0,r.stderr
        text=bundle.read_text(); assert 'Rose&Mary secret source' not in text and 'NO=LEAK' not in text
        p=json.loads(text); assert p['format']=='PFARMA_CI_BUNDLE_V2' and p['algorithm']=='AES-256-GCM'
        dest=root/'open'; r=run('unpack','--bundle',str(bundle),'--destination',str(dest),env=env); assert r.returncode==0,r.stderr; assert (dest/'app.txt').exists(); assert not (dest/'.env').exists()
        bad=env.copy(); bad['PFARMA_CI_BUNDLE_KEY']=base64.b64encode(os.urandom(32)).decode(); r=run('unpack','--bundle',str(bundle),'--destination',str(root/'bad'),env=bad); assert r.returncode!=0
    print('PASS: PFARMA_CI_BUNDLE_V2 is opaque, authenticated and fail-closed.')
if __name__=='__main__': main()
