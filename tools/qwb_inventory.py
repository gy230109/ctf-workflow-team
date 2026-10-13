"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse,json,re
from pathlib import Path
BASE=Path(__file__).resolve().parent.parent
def scan(root):
    root=Path(root).resolve(strict=True);rows=[]
    for group in sorted(root.iterdir()):
        if not group.is_dir():continue
        directory=group/'attachments';directory=directory if directory.is_dir() else group
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.name in {'README.md','UPSTREAM-README.md','MANIFEST-files.txt'}:continue
            m=re.match(r'^(Crypto|Pwn|Misc|Web|Reverse|Re|Blockchain|Mobile|DFIR|IOT|AI)',path.name,re.I)
            rows.append({'id':group.name+'/'+path.name,'set':group.name,'file':path.name,
                         'category':m.group(1).lower() if m else 'unknown','bytes':path.stat().st_size,'path':path.relative_to(root).as_posix()})
    attempts=sorted(p.name for p in (BASE/'wp/cases').iterdir() if p.is_dir()) if (BASE/'wp/cases').is_dir() else []
    return {'attachments':rows,'existing_wp_cases':attempts,'solved_cases':[],
            'scope':'metadata only; categories inferred from prefix; WP existence is not success evidence'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',default=str(BASE/'题目库/CTF-Archives'))
    p.add_argument('--output',default=str(BASE/'题目库/_inventory.json'));a=p.parse_args()
    try:
        data=scan(a.root);out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'ok':True,'attachments':len(data['attachments']),'output':str(out)},ensure_ascii=False));return 0
    except Exception as exc:print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 1
if __name__=='__main__':raise SystemExit(main())
