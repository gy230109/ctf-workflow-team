"""Offline TShark adapter; executed only in a per-case Kali work directory."""
import collections
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

CASE=Path(os.environ['CTF_CASE_DIR']).resolve()
WORK=CASE/'work'
HTTP_MAX_FILES=200
HTTP_MAX_BYTES=16*1048576


def bounded(a,key,default,low,high):
    x=a.get(key,default)
    if isinstance(x,bool) or not isinstance(x,int) or not low<=x<=high:raise ValueError(f'{key} must be {low}..{high}')
    return x


def artifact(p,kind='data_export'):
    return {'artifact':p.relative_to(CASE).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
            'kind':kind,'source':'Actual offline TShark output; original PCAP preserved'}


def file_digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def http_export_files(folder):
    """Check the aggregate export budget while TShark is still writing."""
    files=[];size=0
    for path in folder.rglob('*'):
        if path.is_symlink():raise ValueError('HTTP export contains a symbolic link')
        if not path.is_file():continue
        try:size+=path.stat().st_size
        except FileNotFoundError:continue
        files.append(path)
        if len(files)>HTTP_MAX_FILES or size>HTTP_MAX_BYTES:
            raise ValueError('HTTP object export exceeds 200 files / 16 MiB')
    return files


def cleanup_http_export(folder,token,dest=None):
    """Only remove the temporary paths created by this invocation."""
    root=WORK.resolve(strict=True)
    if folder.is_symlink() or folder.name!=f'pcap-http-{token}' or folder.resolve().parent!=root:
        raise ValueError('Refusing to clean an unexpected HTTP export directory')
    if dest is not None:
        if dest.is_symlink() or dest.name!=f'pcap-http-{token}.zip' or dest.resolve().parent!=root:
            raise ValueError('Refusing to clean an unexpected HTTP export ZIP')
        dest.unlink(missing_ok=True)
    if folder.exists():shutil.rmtree(folder)


def run(argv,timeout,export_folder=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(16*1048576,16*1048576))
        resource.setrlimit(resource.RLIMIT_AS,(768*1048576,768*1048576))
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        p=subprocess.Popen(argv,stdout=out,stderr=err,start_new_session=True,preexec_fn=limits)
        try:
            deadline=time.monotonic()+timeout
            while True:
                if export_folder is not None:http_export_files(export_folder)
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('TShark time budget exceeded')
                try:
                    p.wait(timeout=min(.1,remaining) if export_folder is not None else remaining)
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic()>=deadline:raise TimeoutError('TShark time budget exceeded')
            if export_folder is not None:http_export_files(export_folder)
        except BaseException:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait();raise
        out.seek(0);err.seek(0);raw=out.read(2*1048576+1);error=err.read(65536).decode('utf-8','replace')
    if p.returncode:raise RuntimeError(f'TShark exit {p.returncode}: {error[-4000:]}')
    return raw[:2*1048576].decode('utf-8','replace'),len(raw)>2*1048576,error


def main(a):
    value=a.get('target')
    if not isinstance(value,str) or not value:raise ValueError('Provide local_file or same-case target')
    target=(WORK/value).resolve(strict=True)
    if not target.is_relative_to(CASE) or not target.is_file() or target.stat().st_size>512*1048576:
        raise ValueError('PCAP must be a same-case regular file of at most 512 MiB')
    packets=bounded(a,'max_packets',20000,1,200000);limit=bounded(a,'limit',100,1,500)
    timeout=bounded(a,'_budget_seconds',60,5,600)-2
    argv=['tshark','-n','-r',str(target),'-c',str(packets)]
    action=a.get('action','summary');token=uuid.uuid4().hex[:12]
    result={'ok':True,'action':action,'max_packets':packets,'input_sha256':file_digest(target),
            'scope':'仅离线分析所读包；不是穷尽检查或答案验证。'}
    if action=='follow':
        stream=bounded(a,'stream_id',0,0,1000000)
        text,truncated,stderr=run(argv+['-q','-z',f'follow,tcp,ascii,{stream}'],timeout)
        result.update(stream_id=stream,text=text[:65536],output_truncated=truncated or len(text)>65536)
        dest=WORK/f'pcap-follow-{token}.txt';dest.write_text(text,encoding='utf-8')
    elif action=='http_objects':
        folder=WORK/f'pcap-http-{token}';folder.mkdir()
        manifest=[];dest=WORK/f'pcap-http-{token}.zip';complete=False;zip_created=False
        try:
            text,truncated,stderr=run(argv+['--export-objects','http,'+str(folder),'-q'],timeout,export_folder=folder)
            files=http_export_files(folder)
            with dest.open('xb') as zip_stream:
                zip_created=True
                with zipfile.ZipFile(zip_stream,'w',zipfile.ZIP_DEFLATED) as z:
                    for p in files:
                        if not p.resolve().is_relative_to(folder.resolve()):raise ValueError('Export escaped output directory')
                        data=p.read_bytes();name=p.relative_to(folder).as_posix()
                        manifest.append({'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()});z.writestr('objects/'+name,data)
                    z.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
            complete=True
        finally:
            cleanup_http_export(folder,token,dest if zip_created and not complete else None)
        result.update(objects=manifest,count=len(manifest),output_truncated=truncated,
                      scope='离线导出的 HTTP 对象；压缩包内文件未运行，内容仍需分析验证。')
    else:
        if action in ('summary','streams'):
            fields=['frame.number','frame.len','frame.protocols','ip.src','ipv6.src','ip.dst','ipv6.dst','tcp.stream','udp.stream']
            filt=None
        elif action=='dns':
            fields=['frame.number','dns.id','dns.qry.name','dns.a','dns.aaaa','dns.txt'];filt='dns'
        elif action=='usb':
            fields=['frame.number','usb.device_address','usb.endpoint_address','usb.capdata'];filt='usb.capdata'
            result['scope']='USB 原始 capdata 与包号；不是自动恢复的键盘文本。字段支持取决于实际 TShark。'
        else:raise ValueError('Unsupported PCAP action')
        if filt:argv+=['-Y',filt]
        argv+=['-T','fields','-E','header=y','-E','quote=d','-E','separator=/t']
        for field in fields:argv+=['-e',field]
        text,truncated,stderr=run(argv,timeout)
        rows=list(csv.DictReader(io.StringIO(text),delimiter='\t'))
        if action=='summary':
            protocols=collections.Counter(r.get('frame.protocols','') for r in rows)
            result.update(packets_read=len(rows),captured_frame_bytes=sum(int(r.get('frame.len') or 0) for r in rows),protocols=dict(protocols.most_common(40)))
        elif action=='streams':
            streams={}
            for r in rows:
                for proto in ('tcp','udp'):
                    n=r.get(proto+'.stream')
                    if n:
                        key=proto+':'+n;entry=streams.setdefault(key,{'protocol':proto,'stream_id':int(n),'packets':0,'first_frame':int(r['frame.number']),
                            'source':r.get('ip.src') or r.get('ipv6.src'),'destination':r.get('ip.dst') or r.get('ipv6.dst')})
                        entry['packets']+=1
            result.update(streams=list(streams.values())[:limit],total_streams=len(streams),rows_limited=len(streams)>limit)
        else:result.update(rows=rows[:limit],total_rows=len(rows),rows_limited=len(rows)>limit)
        result['output_truncated']=truncated
        dest=WORK/f'pcap-{action}-{token}.tsv';dest.write_text(text,encoding='utf-8')
    result.update(command=argv,stderr=stderr,evidence_artifacts=[artifact(dest)],artifact=dest.relative_to(CASE).as_posix(),sha256=artifact(dest)['sha256'])
    return result


if __name__=='__main__':
    try:result=main(json.loads(Path(sys.argv[1]).read_text())['args'])
    except Exception as e:result={'ok':False,'error':str(e),'error_code':'pcap_operation_failed'}
    print(json.dumps(result,ensure_ascii=False));sys.exit(0 if result.get('ok') else 1)
