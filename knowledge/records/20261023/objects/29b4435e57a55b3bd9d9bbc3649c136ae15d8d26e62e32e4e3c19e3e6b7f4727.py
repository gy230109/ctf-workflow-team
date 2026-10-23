import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = Path(__file__).resolve().parent
URL = 'http://127.0.0.1:11435'

def request(path, data=None, timeout=3):
    req = urllib.request.Request(URL + path, data=None if data is None else json.dumps(data).encode(),
                                 headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)

server = None
log = None
started = time.monotonic()
try:
    try:
        tags = request('/api/tags')
    except Exception:
        env = dict(os.environ, OLLAMA_HOST='127.0.0.1:11435', OLLAMA_MODELS='D:/ollama/models')
        log = (ROOT/'ollama-probe.log').open('ab')
        server = subprocess.Popen(['[USER_HOME]/AppData/Local/Programs/Ollama/ollama.exe','serve'],
            env=env, stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW)
        for attempt in range(30):
            time.sleep(.3)
            try:
                tags = request('/api/tags'); break
            except Exception:
                if server.poll() is not None: raise RuntimeError('Ollama server exited')
        else: raise RuntimeError('Ollama server did not become ready')
    available = {x['name'] for x in tags['models']}
    model = 'qwen3:8b'
    if model not in available: raise RuntimeError('Qwen3:8b is not installed')
    source = (ROOT/'source/task.py').read_text(encoding='utf-8').replace('\r','').split("'''")[0]
    prompt = ('请独立分析下面这道 CTF 密码题，给出最可行的分步数学攻击路线和验算条件。'
              '本轮只分析，不执行代码、不猜 flag。附件另给出所有模数、指数、密文的整数。'
              '源码 return 中变量名有笔误，按生成公式和输出参数理解。简洁回答。\n' + source)
    result = request('/api/generate', {'model':model,'prompt':prompt,'think':False,'stream':False,
        'keep_alive':0,'options':{'num_ctx':4096,'num_predict':1400,'temperature':.2}}, timeout=100)
    result['role'] = 'independent_local_model_hypothesis'
    result['wall_seconds'] = round(time.monotonic()-started,3)
    (ROOT/'local-model-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'model':model,'seconds':result['wall_seconds'],'response':result.get('response'),
                      'done_reason':result.get('done_reason')},ensure_ascii=False),flush=True)
except Exception as exc:
    (ROOT/'local-model-error.json').write_text(json.dumps({'error':str(exc)},ensure_ascii=False),encoding='utf-8')
    print('LOCAL MODEL ERROR:',str(exc),flush=True)
    raise
finally:
    if server is not None:
        try: request('/api/generate',{'model':'qwen3:8b','keep_alive':0},timeout=5)
        except Exception: pass
        server.terminate()
        try: server.wait(timeout=5)
        except subprocess.TimeoutExpired: server.kill()
    if log is not None: log.close()
