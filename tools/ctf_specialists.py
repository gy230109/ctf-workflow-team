"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import uuid

import ctf_os_runtime as runtime
import ctf_wp as wp
import ctf_reverse_route

BASE=Path(__file__).resolve().parent.parent
CONFIG=BASE/"config/ctf_specialists.local.json"
WORKER=Path(__file__).with_name("ctf_specialist_worker.py")
PROFILES={
 "web":{"packages":["requests","beautifulsoup4","playwright"],"modules":["requests","bs4","playwright"],
        "commands":["chromium","sqlmap","ffuf"],"tools":["web_http_inspect","web_html_parse","web_jwt_decode","web_browser_capture"],
        "route":["读取题面与已授权 URL/源码","分析 HTTP、表单和 JWT","针对证据验证假设","采集真实网页截图并留 WP"]},
 "pwn":{"packages":["pwntools"],"modules":["pwn"],"commands":["gdb"],
        "tools":["pwn_elf_info","pwn_cyclic","pwn_rop_search"],
        "route":["检查 ELF 架构与保护","依据实际崩溃值计算 cyclic 偏移","检索 ROP gadget","在题目 VM 验证脚本与结果"]},
 "reverse":{"packages":["lief","capstone","angr<10","bitstring<5"],"modules":["lief","capstone","angr"],"commands":["gdb"],
        "tools":["reverse_binary_info","rea_status","rea_ops","rea_run","reverse_disassemble","reverse_symbolic"],
        "route":["依据附件魔数分型；提供 local_file 返回明确分支","原生 PE：rea_status/rea_ops 后用 rea_run inspect，再对目标函数调用 function；.NET 用 inspect-managed-members","ELF 走 Kali Ghidra/GDB；APK/DEX 走 jadx；源码先读源码","将候选交给真实题目程序验证，记录成功和拒绝；需要时换算 ASLR 地址"]},
 "crypto":{"packages":["sympy","z3-solver","fpylll","cysignals","pycryptodome"],
        "modules":["sympy","z3","fpylll","Crypto"],"commands":[],
        "tools":["crypto_factor","crypto_crt","crypto_z3","crypto_lll","crypto_aes_decrypt"],
        "route":["确认算法与已知数据；先做便宜检查","数论/约束/格约简按假设选择","使用已证明的密钥进行解密","核对数学恒等式与真实输出"]},
 "misc":{"packages":["pillow"],"modules":["PIL"],"commands":["file","7z","exiftool"],
        "tools":["misc_file_inspect","misc_archive_list","misc_image_inspect"],
        "route":["核对原附件摘要、魔数与字符串","只列压缩包内容，不自动解压","检查图片元数据与格式尾部","按实际特征决定下一种隐写/编码方法"]},
 "forensics":{"packages":["scapy","volatility3"],"modules":["scapy","volatility3"],"commands":["tshark"],
        "tools":["forensics_pcap_summary","forensics_volatility"],
        "route":["保留原始证据与摘要","离线汇总流量并定位会话","内存取证先检查插件与符号需求","从真实工具输出复核结论并留 WP"]}}


def settings():
    cfg=json.loads(CONFIG.read_text(encoding="utf-8-sig")) if CONFIG.is_file() else {}
    if not isinstance(cfg,dict):raise ValueError("specialist configuration must be an object")
    return cfg


def arguments(a):
    if not isinstance(a,dict):raise ValueError("arguments must be an object")
    if a.get("request_file"):
        path=Path(a["request_file"])
        if not path.is_file() or path.stat().st_size>65536:raise ValueError("request_file must be JSON of at most 64 KiB")
        data=json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data,dict):raise ValueError("request_file must contain an object")
        data.update({k:v for k,v in a.items() if k!="request_file"})
        return data
    return dict(a)


def checked_case(a):
    case=str(a.get("case") or a.get("wp_case") or ("specialists_"+uuid.uuid4().hex[:24]))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",case):raise ValueError("invalid case identifier")
    if a.get("case") and a.get("wp_case") and a["case"]!=a["wp_case"]:raise ValueError("case and wp_case must identify the same challenge")
    return case


def execute(operation,args):
    a=arguments(args);case=checked_case(a);cfg=settings()
    if cfg.get("enabled") is not True:return {"ok":False,"error":"specialists disabled","error_code":"specialists_disabled"}
    python=cfg.get("python")
    if not isinstance(python,str) or not PurePosixPath(python).is_absolute():raise ValueError("configure an absolute Kali specialist Python path")
    timeout=a.get("timeout",cfg.get("timeout_seconds",60))
    if isinstance(timeout,bool) or not isinstance(timeout,int) or not 1<=timeout<=600:raise ValueError("timeout must be 1..600 seconds")
    payload=dict(a);payload["_budget_seconds"]=timeout
    files=[]
    if a.get("local_file"):
        if a.get("target"):raise ValueError("provide either local_file or a same-case Kali target")
        original=Path(a["local_file"]).resolve(strict=True)
        if not original.is_file():raise ValueError("local_file must be a regular file")
        files.append(str(original));payload["target"]="../input/"+original.name
        payload.pop("local_file",None)
    folder=BASE/"logs/specialists/requests"/uuid.uuid4().hex
    folder.mkdir(parents=True,exist_ok=False)
    worker_hash=hashlib.sha256(WORKER.read_bytes()).hexdigest()
    staged=folder/("specialist-worker-"+worker_hash[:16]+".py")
    shutil.copyfile(WORKER,staged)
    req=folder/("request-"+uuid.uuid4().hex+".json")
    request={"operation":operation,"args":payload}
    serialized=json.dumps(request,ensure_ascii=False)
    if len(serialized.encode())>65536:raise ValueError("specialist request exceeds 64 KiB")
    req.write_text(serialized,encoding="utf-8")
    files.extend([str(staged),str(req)])
    upload=runtime.bridge_call(["put",case,*files],timeout=180)
    if runtime.failed(upload) or upload.get("verified") is not True:
        return {"ok":False,"error":"specialist upload/hash verification failed","error_code":"upload_failed","detail":upload}
    result=runtime.kali_execute({"case":case,"timeout":timeout},[python,"../input/"+staged.name,"../input/"+req.name])
    try:data=json.loads(result.get("stdout",""))
    except (ValueError,TypeError):
        return {"ok":False,"error":"specialist worker did not return JSON","error_code":"worker_failed","execution":result}
    if not isinstance(data,dict):
        return {"ok":False,"error":"specialist JSON must be an object","error_code":"invalid_worker_response","execution":result}
    out={"ok":not runtime.failed(result) and not runtime.failed(data),"data":data,"execution":result,
         "case":case,"on":"kali","transport":"verified_bridge","upload_verified":True,
         "source_status":cfg.get("source_status","unknown")}
    if not out["ok"]:out.update(error=data.get("error") or "specialist operation failed",error_code=data.get("error_code","operation_failed"))
    if out["ok"] and data.get("artifact"):
        artifact=PurePosixPath(str(data["artifact"]))
        if artifact.is_absolute() or ".." in artifact.parts or artifact.parts[0] not in ("work","results"):raise ValueError("worker artifact escaped case")
        fetched=runtime.bridge_call(["fetch",case,str(artifact)],timeout=90)
        out["artifact_fetch"]=fetched
        if runtime.failed(fetched) or fetched.get("verified") is not True or (data.get("sha256") and fetched.get("sha256")!=data["sha256"]):
            out.update(ok=False,error="artifact download/hash verification failed",error_code="artifact_fetch_failed")
        else:
            out["artifact_path"]=fetched["local_path"]
            if a.get("wp_case"):
                out["screenshot_record"]=wp.capture({"case":a["wp_case"],"mode":"file","file_path":fetched["local_path"],
                    "source":"Kali Chromium actual webpage screenshot; verified SSH download SHA256",
                    "caption":"网页实际画面："+str(data.get("title") or "")})
    return out


def profile(a):
    a=arguments(a);category=str(a["category"]).lower()
    if category not in PROFILES:raise ValueError("category must be web/pwn/reverse/crypto/misc/forensics")
    result={"category":category,**PROFILES[category],"environment":"Kali specialist venv through existing bridge; PE static analysis uses host REA",
            "next_step":"ctf_specialist_status 检查实际依赖；每题 wp_init，后续调用加同一 wp_case",
            "route_is_not_a_solution":True,"limits":{"default_timeout_seconds":60,"default_memory_mb":1536}}
    if category=='reverse':result['reverse_routing']=ctf_reverse_route.route(a)
    return result


def install(a):
    a=arguments(a)
    if a.get("confirm") is not True:raise ValueError("confirm=true required")
    category=a.get("category")
    if category not in (*PROFILES,"all"):raise ValueError("provide an explicit category or all")
    selected=PROFILES.values() if category=="all" else [PROFILES[category]]
    packages=sorted({p for profile in selected for p in profile["packages"]})
    cfg=settings();python=cfg["python"];index=cfg.get("pip_index","https://pypi.org/simple")
    if index not in ("https://pypi.org/simple","https://mirrors.aliyun.com/pypi/simple"):
        raise ValueError("configured package index is not an approved registry endpoint")
    timeout=a.get("timeout",600)
    if isinstance(timeout,bool) or not isinstance(timeout,int) or not 1<=timeout<=600:raise ValueError("timeout must be 1..600 seconds")
    code='import fcntl,json,pathlib,subprocess,sys; lock=(pathlib.Path(sys.prefix)/".install.lock").open("a"); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB); sys.exit(subprocess.run([sys.executable,"-m","pip","install","--prefer-binary","--index-url",sys.argv[1],*json.loads(sys.argv[2])]).returncode)'
    result=runtime.kali_execute({"case":checked_case(a),"timeout":timeout},
        [python,"-c",code,index,json.dumps(packages)])
    return {"ok":not runtime.failed(result),"category":category,"packages":packages,"execution":result,
            "note":"Python packages only; system commands are reused and checked separately",
            **({"error":"category package installation failed"} if runtime.failed(result) else {})}


def schema(properties=None,required=None):
    common={"case":{"type":"string"},"request_file":{"type":"string"},"timeout":{"type":"integer"},
            "local_file":{"type":"string"},"target":{"type":"string"},"memory_mb":{"type":"integer"}}
    common.update(properties or {})
    return {"type":"object","properties":common,"required":required or []}


S=lambda: {"type":"string"}
I=lambda: {"type":"integer"}
B=lambda: {"type":"boolean"}
A=lambda: {"type":"array"}
O=lambda: {"type":"object"}

SPECS={
 "web_http_inspect":("web_http","读取明确题目 URL 的 HTTP/HTML 证据（需要 confirm=true）",{"url":S(),"confirm":B(),"network_timeout":I(),"follow_redirects":B()}),
 "web_html_parse":("web_html","解析已有 HTML 的标题、表单、链接；不自动访问",{"html":S()}),
 "web_jwt_decode":("web_jwt","解析 JWT 头与载荷；不验证签名、不认证声明",{"token":S()}),
 "web_browser_capture":("web_capture","Kali Chromium 真实截图、摘要回收并自动记入指定 WP",{"url":S(),"confirm":B(),"allow_origins":A()}),
 "pwn_elf_info":("pwn_elf","Pwntools 读取 ELF 架构、保护和符号；不运行样本",{}),
 "pwn_cyclic":("pwn_cyclic","生成 cyclic 或根据已有崩溃值有界计算偏移",{"action":S(),"length":I(),"max_length":I(),"value":{"type":["string","integer"]},"n":I()}),
 "pwn_rop_search":("pwn_rop","ROPgadget 有界检索；不执行二进制",{"depth":I(),"query":S()}),
 "reverse_binary_info":("reverse_binary","LIEF 静态读取 PE/ELF 等文件结构与文件地址",{}),
 "reverse_disassemble":("reverse_disassemble","Capstone 对明确字节区段反汇编",{"arch":S(),"code_hex":S(),"offset":I(),"size":I(),"address":I(),"limit":I()}),
 "reverse_symbolic":("reverse_symbolic","angr 有界符号执行；仅产候选，须用实际题目验证",{"stdin_length":I(),"find_addresses":A(),"avoid_addresses":A(),"find_text":S(),"max_steps":I(),"printable":B()}),
 "crypto_factor":("crypto_factor","有界因数分解，区分部分/完整结果并校验乘积",{"number":{"type":["string","integer"]},"limit":I()}),
 "crypto_crt":("crypto_crt","中国剩余定理并逐项验证同余",{"moduli":A(),"values":A()}),
 "crypto_z3":("crypto_z3","结构化或 SMT-LIB2 的 Z3 约束求解；不执行 Python",{"variables":O(),"constraints":A(),"smt2":S(),"solver_timeout_ms":I()}),
 "crypto_lll":("crypto_lll","fpylll 格基约简并核对变换矩阵",{"basis":A()}),
 "crypto_aes_decrypt":("crypto_aes","使用明确密钥进行 CBC/ECB/GCM 解密",{"mode":S(),"key_hex":S(),"ciphertext_hex":S(),"iv_hex":S(),"nonce_hex":S(),"tag_hex":S(),"aad_hex":S(),"unpad":B()}),
 "misc_file_inspect":("misc_file","文件摘要、魔数、样本熵和 ASCII 字符串",{}),
 "misc_archive_list":("misc_archive","只列压缩包内容、标记越界路径；不解压",{}),
 "misc_image_inspect":("misc_image","图片元数据和格式尾部；不代表穷尽隐写分析",{}),
 "forensics_pcap_summary":("forensics_pcap","Scapy 离线逐包汇总，限制读取量；不发包",{"max_packets":I()}),
 "forensics_volatility":("forensics_volatility","Volatility3 离线插件入口；真实内存分析需要镜像与符号",{"plugin":S()})}

TOOLS={"ctf_profile":(profile,"按题型返回工具路线；reverse 提供 local_file 可按魔数分型并显式选择 REA",schema({"category":S(),"subtype":S()})),
       "ctf_specialist_status":(lambda a:execute("status",a),"现测 Kali 专项环境依赖，不调用模型、不解题",schema()),
       "ctf_install_category":(install,"在专项 venv 按明确题型补依赖（confirm=true）",schema({"category":S(),"confirm":B()}))}
for name,(operation,description,properties) in SPECS.items():
    TOOLS[name]=(lambda a,op=operation:execute(op,a),description,schema(properties))
DANGEROUS={"ctf_install_category","web_http_inspect","web_browser_capture"}

# Optional native additions have their own actual dependency status. Their
# availability must not be inferred from the Python-only specialist probe.
PROFILES['web']['tools'].append('web_browser_session')
PROFILES['web']['route'].append('需要连续交互时 web_browser_session；每题独立浏览器，只访问明确许可的同源')
PROFILES['reverse']['tools']+=['ctf_runtime_status','kali_debug_session','qemu_run']
PROFILES['pwn']['tools']+=['ctf_runtime_status','kali_debug_session']
PROFILES['pwn']['route'].append('实际动态调试使用 kali_debug_session/Pwndbg；结束后 close')
PROFILES['crypto']['tools'].append('crypto_library')
PROFILES['crypto']['route'].append('高阶方法查 crypto_library，核对适用条件和源码后在 Sage 中导入使用')
PROFILES['misc']['tools'].append('misc_stego')
PROFILES['misc']['route'].append('PNG/BMP 用 zsteg；JPEG/WAV 的 steghide 检查/提取与显式词表检索通过 misc_stego')
