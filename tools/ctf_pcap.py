"""Team CTF workflow component. See README.md for configuration and verified scope."""
from pathlib import Path
import ctf_extensions

WORKER=Path(__file__).with_name('ctf_pcap_worker.py')


def analyze(a):
    return ctf_extensions.execute('pcap',a,worker=WORKER,require_config=False,python='/usr/bin/python3')


TOOLS={'forensics_pcap':(analyze,'离线 PCAP：summary 汇总、streams 会话、follow TCP 原始流、http_objects 导出、dns 查询、usb 原始 HID 数据。返回包号/流号和摘要，自动留 WP；不发包、不运行附件。',
 {'type':'object','properties':{'case':{'type':'string'},'local_file':{'type':'string'},'target':{'type':'string'},
 'action':{'type':'string','enum':['summary','streams','follow','http_objects','dns','usb'],'default':'summary'},
 'stream_id':{'type':'integer'},'max_packets':{'type':'integer','default':20000},'limit':{'type':'integer','default':100},
 'timeout':{'type':'integer','default':60},'request_file':{'type':'string'}},'required':[]})}
