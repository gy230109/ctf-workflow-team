"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse
import json
from pathlib import Path
import sys

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool');parser.add_argument('--request',required=True)
    parser.add_argument('--wp-case');parser.add_argument('--case')
    args=parser.parse_args()
    try:
        path=Path(args.request)
        if path.stat().st_size>65536:raise ValueError('Request exceeds 64 KiB')
        data=json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(data,dict):raise ValueError('Request must be a JSON object')
        if args.wp_case:data['wp_case']=args.wp_case
        if args.case:data['case']=args.case
        import ctf_os
        result=ctf_os.call_tool(args.tool,data)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0 if result.get('ok') else 1
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 1
if __name__=='__main__':raise SystemExit(main())
