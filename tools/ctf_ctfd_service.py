"""Team CTF workflow component. See README.md for configuration and verified scope."""
import argparse,json,os,socket,subprocess,sys,time
from pathlib import Path
from ctf_bootstrap import BASE,Bootstrap,FileLock,HIDDEN,read_json,write_json

def configured():
    cfg=read_json(BASE/'config/startup.json')
    return cfg.get('ctfd',{})

def listening(port):
    with socket.socket() as s:
        s.settimeout(1);return s.connect_ex(('127.0.0.1',port))==0

def ensure():
    cfg=configured()
    if cfg.get('enabled') is not True:return {'enabled':False}
    folder=BASE/'logs/ctfd-service';folder.mkdir(exist_ok=True)
    # The file lock in serve() makes repeated logon/start requests harmless.
    with (folder/'guardian.log').open('ab') as log:
        p=subprocess.Popen([sys.executable,'-X','utf8',str(Path(__file__)),'--serve'],cwd=BASE,stdout=log,stderr=log,creationflags=HIDDEN)
    return {'requested':True,'launcher_pid':p.pid,'url':'http://127.0.0.1:'+str(cfg['local_port'])}

def serve():
    cfg=configured();folder=BASE/'logs/ctfd-service';folder.mkdir(exist_ok=True)
    with FileLock(folder/'tunnel.lock'):
        child=None
        try:
            while True:
                if child is not None and child.poll() is None:
                    time.sleep(5);continue
                if listening(cfg['local_port']):raise RuntimeError('CTFd local port is occupied by another process; nothing was stopped')
                try:
                    b=Bootstrap();ip=b.muteki_ip();vm=b.cfg['muteki'];root=Path(vm['vmx']).parent
                    # Only the service owned by this deployment may be resumed.
                    recovery="""python3 - <<'PY'
import subprocess
unit='ctf-system-ctfd.service'
description=subprocess.check_output(['systemctl','show','-p','Description','--value',unit],text=True).strip()
if description!='CTF system CTFd local portal':raise ValueError('CTFd service ownership mismatch')
subprocess.run(['sudo','-n','systemctl','start',unit],check=True)
subprocess.run(['systemctl','is-active','--quiet',unit],check=True)
print('ctfd_service_ready')
PY"""
                    b.ssh(ip,recovery,timeout=25)
                    argv=[b.kali['ssh'],'-N','-T','-i',str(root/'private/id_ed25519'),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                        '-o','HostKeyAlias='+vm['host_key_alias'],'-o','UserKnownHostsFile='+(root/'known_hosts').as_posix(),
                        '-o','ConnectTimeout=5','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2',
                        '-L','127.0.0.1:'+str(cfg['local_port'])+':127.0.0.1:'+str(cfg['guest_port']),vm['user']+'@'+ip]
                    with (folder/'ssh.log').open('ab') as log:child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log,creationflags=HIDDEN)
                    write_json(folder/'status.json',{'state':'connecting','ssh_pid':child.pid,'address':ip,'url':'http://127.0.0.1:'+str(cfg['local_port'])})
                except Exception as e:
                    write_json(folder/'status.json',{'state':'waiting','error':str(e)[:800]})
                    time.sleep(10)
        finally:
            if child and child.poll() is None:child.terminate();child.wait(timeout=10)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--serve',action='store_true');args=parser.parse_args()
    if args.serve:
        try:serve()
        except RuntimeError as e:
            if 'Another CTF startup' not in str(e):raise
    else:print(json.dumps(ensure()))

if __name__=='__main__':main()
