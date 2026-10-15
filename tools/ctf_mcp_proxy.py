"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse,json,sys,urllib.error,urllib.request

def main():
    p=argparse.ArgumentParser();p.add_argument('--stdio',action='store_true');p.add_argument('--url',default='http://127.0.0.1:8787')
    p.add_argument('--log');p.add_argument('--audit');a=p.parse_args()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for line in sys.stdin:
        request=None
        try:
            request=json.loads(line)
            req=urllib.request.Request(a.url.rstrip('/')+'/mcp',data=json.dumps(request).encode(),headers={'Content-Type':'application/json'})
            with opener.open(req,timeout=650) as response:result=json.load(response)
            if request.get('method')=='initialize' and isinstance(result.get('result'),dict):
                with opener.open(a.url.rstrip('/')+'/version',timeout=5) as version:info=json.load(version)
                result['result']['serverInfo']['version']=info['release']+'-'+info['source_fingerprint'][:12]
            if result is not None:print(json.dumps(result,ensure_ascii=False),flush=True)
        except Exception as e:
            if isinstance(request,dict) and 'id' in request:
                print(json.dumps({'jsonrpc':'2.0','id':request['id'],'error':{'code':-32000,'message':'CTF runtime unavailable: '+str(e)}}),flush=True)
            else:print('CTF runtime notification failed: '+type(e).__name__,file=sys.stderr,flush=True)
    return 0
if __name__=='__main__':sys.exit(main())
