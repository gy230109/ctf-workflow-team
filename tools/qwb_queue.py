"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse,json
from pathlib import Path
BASE=Path(__file__).resolve().parent.parent
STATES=('todo','extracted','triaged','solving','candidate','verified','blocked','skip')
def load():
    path=BASE/'题目库/_queue.json'
    if path.is_file():return json.loads(path.read_text(encoding='utf-8-sig'))
    inventory=json.loads((BASE/'题目库/_inventory.json').read_text(encoding='utf-8-sig'))
    return {'items':{a.get('id',a['set']+'/'+a['file']):dict(a,status='todo',note='') for a in inventory['attachments']}}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['list','next','set'],nargs='?',default='list')
    p.add_argument('id',nargs='?');p.add_argument('status',nargs='?',choices=STATES);p.add_argument('--note',default='')
    p.add_argument('--wp-case');p.add_argument('--source-step',type=int);a=p.parse_args()
    try:
        db=load();items=db['items']
        if a.action=='set':
            if a.id not in items or not a.status:raise ValueError('Provide existing ID and status')
            if a.status=='verified':
                if not a.wp_case or not a.source_step:raise ValueError('Verified label requires WP case and evidence step')
                import ctf_wp
                status=ctf_wp.status({'case':a.wp_case})
                if status.get('integrity_verified') is not True:raise ValueError('WP integrity must pass')
                records=[json.loads(line) for line in (BASE/'wp/cases'/a.wp_case/'timeline.jsonl').read_text(encoding='utf-8').splitlines()]
                if not any(r.get('seq')==a.source_step for r in records):raise ValueError('Referenced step does not exist')
            items[a.id].update(status=a.status,note=a.note,wp_case=a.wp_case,source_step=a.source_step)
            (BASE/'题目库/_queue.json').write_text(json.dumps(db,ensure_ascii=False,indent=2),encoding='utf-8')
            result={'updated':a.id,'status':a.status,'status_is_not_platform_acceptance':True}
        elif a.action=='next':
            result=next((dict(v,id=k) for s in ('solving','triaged','extracted','todo') for k,v in sorted(items.items()) if v['status']==s),{'queue_empty':True})
        else:result={'items':items,'count':len(items)}
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0
    except Exception as exc:print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 1
if __name__=='__main__':raise SystemExit(main())
