"""Build included GPL bridge and register an explicitly supplied pinned GUI."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
ROOT=Path(__file__).resolve().parents[1]
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--gui',type=Path,required=True);p.add_argument('--replace',action='store_true');a=p.parse_args()
    config=ROOT/'config/ctf_cracktools.local.json'
    if config.exists() and not a.replace:raise ValueError('Existing configuration retained; inspect status or explicitly use --replace')
    component=ROOT/'tools/cracktools_bridge';release=json.loads((component/'upstream.json').read_text(encoding='utf-8'))
    gui=a.gui.resolve(strict=True)
    if digest(gui)!=release['gui_sha256']:raise ValueError('GUI does not match pinned release SHA256')
    cargo=shutil.which('cargo')
    if not cargo:raise ValueError('Configure Rust cargo and MSVC first')
    built=subprocess.run([cargo,'build','--release','--locked','--manifest-path',str(component/'Cargo.toml')],capture_output=True,text=True,timeout=600)
    if built.returncode:raise RuntimeError(built.stderr[-3000:])
    executable=component/'target/release/ctfcracktools-bridge.exe'
    if not executable.is_file():raise RuntimeError('Expected Windows bridge executable is missing')
    catalog=component/'algorithms.json'
    values={'enabled':True,'tag':release['tag'],'upstream_commit':release['commit'],'gui_executable':str(gui),'gui_executable_sha256':digest(gui),'bridge_executable':str(executable),'bridge_executable_sha256':digest(executable),'catalog_file':str(catalog),'catalog_file_sha256':digest(catalog)}
    config.parent.mkdir(exist_ok=True);config.write_text(json.dumps(values,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'configured':True,'next':'Call cracktools_status and verify an actual conversion'}))
if __name__=='__main__':main()
