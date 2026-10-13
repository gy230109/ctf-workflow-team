"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',required=True);p.add_argument('--target',required=True);p.add_argument('--plan',action='store_true')
    a=p.parse_args()
    try:
        import team_upgrade
        target=Path(a.target).resolve(strict=True)
        if not (target/'tools/ctf_os.py').is_file():raise ValueError('Target is not an existing CTF installation')
        result=team_upgrade.apply(a.source,target,a.plan)
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result['ok'] else 1
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 1
if __name__=='__main__':raise SystemExit(main())
