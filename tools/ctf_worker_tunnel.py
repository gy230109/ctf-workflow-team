"""Team CTF workflow component. See README.md for configuration and verified scope."""
import base64,json,queue,subprocess,threading
from pathlib import Path
import ctf_bootstrap as boot
RELAY='''import http.server,urllib.request,json,sys,socket
gateway,port,forward=json.loads(sys.argv[1])
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
class Relay(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  n=int(self.headers.get('Content-Length','0'))
  if self.path!='/call' or not 0<n<=65536:self.send_error(400);return
  req=urllib.request.Request('http://127.0.0.1:'+str(forward)+'/call',data=self.rfile.read(n),headers={'Content-Type':'application/json','X-CTF-Case-Token':self.headers.get('X-CTF-Case-Token','')})
  try:
   with opener.open(req,timeout=340) as response:body=response.read(4*1024*1024);status=response.status
  except urllib.error.HTTPError as e:body=e.read();status=e.code
  except Exception:body=b'{"ok":false,"error":"forward unavailable"}';status=502
  self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
server=http.server.ThreadingHTTPServer((gateway,port),Relay)
print(json.dumps({'ready':True,'port':server.server_address[1]}),flush=True)
server.serve_forever()
'''

class WorkerTunnel:
    def __init__(self,local_port):self.local_port=local_port;self.process=None
    def start(self):
        b=boot.Bootstrap();address=b.muteki_ip()
        code="import socket,json,subprocess;g=json.loads(subprocess.check_output(['docker','network','inspect','bridge']))[0]['IPAM']['Config'][0]['Gateway'];s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();print(json.dumps({'gateway':g,'forward':p}))"
        remote=json.loads(b.ssh(address,"python3 -c "+__import__('shlex').quote(code),timeout=15))
        cfg=b.cfg['muteki'];root=Path(cfg['vmx']).parent
        payload=base64.b64encode(RELAY.encode()).decode()
        params=json.dumps([remote['gateway'],0,remote['forward']],separators=(',',':'))
        command="python3 -u -c 'import base64;exec(base64.b64decode(\""+payload+"\"))' '"+params+"'"
        args=[b.kali['ssh'],'-T','-i',str(root/'private/id_ed25519'),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','HostKeyAlias='+cfg['host_key_alias'],'-o','UserKnownHostsFile='+(root/'known_hosts').as_posix(),'-o','ExitOnForwardFailure=yes',
            '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-R',f"127.0.0.1:{remote['forward']}:127.0.0.1:{self.local_port}",cfg['user']+'@'+address,command]
        self.process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        ready=queue.Queue()
        threading.Thread(target=lambda:ready.put(self.process.stdout.readline()),daemon=True).start()
        try:
            line=ready.get(timeout=20);state=json.loads(line)
            if not state.get('ready'):raise RuntimeError('relay failed readiness')
            self.url=f"http://{remote['gateway']}:{state['port']}"
            # Prove that this same Docker image can reach the scoped gateway before dispatch.
            return self
        except Exception:self.close();raise
    def close(self):
        if self.process:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
            for stream in (self.process.stdout,self.process.stderr):stream.close()
