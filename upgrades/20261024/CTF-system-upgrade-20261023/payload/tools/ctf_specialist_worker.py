"""Bounded CTF operations executed by the existing Kali bridge.

This is a local compatibility implementation, not the pending cloud source export.
It never submits flags, runs a loaded binary natively, or scans a network.
"""
import ast
import base64
from collections import Counter
import contextlib
import hashlib
import importlib
import importlib.metadata as metadata
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import uuid
import zipfile

MODULES = {"requests":"requests", "bs4":"beautifulsoup4", "playwright":"playwright",
           "pwn":"pwntools", "lief":"lief", "capstone":"capstone", "angr":"angr",
           "sympy":"sympy", "z3":"z3-solver", "fpylll":"fpylll", "Crypto":"pycryptodome",
           "PIL":"pillow", "scapy":"scapy", "volatility3":"volatility3"}
COMMANDS = ["gdb", "tshark", "sqlmap", "ffuf", "chromium", "7z", "exiftool", "file"]


def bounded(value, low, high, name):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def hexbytes(value, name):
    if not isinstance(value, str) or len(value) > 131072:
        raise ValueError(f"{name} must be bounded hex text")
    return bytes.fromhex(value)


def file_path(a):
    path = Path(a["target"]).resolve(strict=True)
    case = Path(os.environ["CTF_CASE_DIR"]).resolve()
    if not path.is_file() or not path.is_relative_to(case):
        raise ValueError("target must be a regular file inside this case")
    return path


def command(argv, timeout=30):
    proc = subprocess.run(argv, capture_output=True, timeout=timeout)
    return {"returncode":proc.returncode,
            "stdout":proc.stdout[:32768].decode("utf-8","replace"),
            "stderr":proc.stderr[:8192].decode("utf-8","replace"),
            "output_truncated":len(proc.stdout)>32768 or len(proc.stderr)>8192}


def inspect_status(a):
    items = {}
    for name, dist in MODULES.items():
        present = importlib.util.find_spec(name) is not None
        try:version=metadata.version(dist)
        except metadata.PackageNotFoundError:version=None
        usable=False;error_type=None
        if present:
            try:importlib.import_module(name);usable=True
            except Exception as exc:error_type=type(exc).__name__
        items[name] = {"available":present,"version":version,"import_usable":usable,"import_error_type":error_type}
    return {"python":sys.executable,"modules":items,
            "commands":{n:shutil.which(n) for n in COMMANDS},"scope":"dependency discovery, not solving"}


def web_html(a):
    from bs4 import BeautifulSoup
    html = file_path(a).read_text(encoding="utf-8",errors="replace")[:262144] if a.get("target") else str(a.get("html",""))[:262144]
    soup = BeautifulSoup(html,"html.parser")
    forms=[]
    for form in soup.find_all("form")[:32]:
        forms.append({"action":form.get("action",""),"method":form.get("method","get").upper(),
                      "fields":[{"name":x.get("name"),"type":x.get("type",x.name)} for x in form.find_all(["input","select","textarea"])[:64]]})
    return {"title":soup.title.get_text(strip=True) if soup.title else None,"forms":forms,
            "links":[x.get("href") for x in soup.find_all("a",href=True)[:100]],
            "script_sources":[x.get("src") for x in soup.find_all("script",src=True)[:64]]}


def web_http(a):
    if a.get("confirm") is not True:raise ValueError("confirm=true required")
    import requests
    from urllib.parse import urlparse
    url=str(a["url"])
    if urlparse(url).scheme not in ("http","https") or urlparse(url).username:
        raise ValueError("provide an explicit HTTP(S) challenge URL without URL credentials")
    response=requests.get(url,timeout=bounded(a.get("network_timeout",15),1,30,"network_timeout"),
                          allow_redirects=a.get("follow_redirects") is True,stream=True)
    pieces=[];length=0
    # Stop receiving even when Content-Length is absent or a stream is infinite.
    for piece in response.iter_content(65536):
        remaining=262144-length
        pieces.append(piece[:remaining]);length+=min(len(piece),remaining)
        if length>=262144:break
    body=b"".join(pieces)
    response.close()
    result={"url":response.url,"status_code":response.status_code,
            "headers":{k:v for k,v in response.headers.items() if k.lower() not in ("set-cookie","authorization")},
            "body_preview":body[:12000].decode(response.encoding or "utf-8","replace"),
            "body_sha256":hashlib.sha256(body).hexdigest(),"sample_bytes":len(body),
            "body_is_sample":True}
    if "html" in response.headers.get("Content-Type","").lower():result["html_analysis"]=web_html({"html":body.decode(response.encoding or "utf-8","replace")})
    return result


def web_jwt(a):
    parts=str(a["token"]).split(".")
    if len(parts)!=3 or any(len(p)>32768 for p in parts):raise ValueError("JWT must have three bounded parts")
    decode=lambda p:json.loads(base64.urlsafe_b64decode(p+"="*((-len(p))%4)))
    return {"header":decode(parts[0]),"payload":decode(parts[1]),"signature_verified":False,
            "note":"decoded claims are untrusted; no signature/authentication verification"}


def web_capture(a):
    if a.get("confirm") is not True:raise ValueError("confirm=true required")
    from urllib.parse import urlparse
    from playwright.sync_api import sync_playwright
    url=str(a["url"])
    if urlparse(url).scheme not in ("http","https") or urlparse(url).username:raise ValueError("HTTP(S) URL required")
    def origin(value):
        p=urlparse(value)
        if p.scheme not in ("http","https") or not p.hostname or p.username:raise ValueError("allow_origins must contain HTTP(S) origins without credentials")
        return (p.scheme,p.hostname,p.port or (443 if p.scheme=="https" else 80))
    extras=a.get("allow_origins",[])
    if not isinstance(extras,list) or len(extras)>16:raise ValueError("allow_origins must be a bounded list")
    allowed={origin(url),*(origin(x) for x in extras)};blocked=[]
    executable=shutil.which("chromium")
    if not executable:raise RuntimeError("chromium executable missing")
    name="browser-"+uuid.uuid4().hex+".png"
    path=Path(os.environ["CTF_WORK_DIR"])/name
    import psutil
    stop=threading.Event();usage={"peak":0,"exceeded":False}
    budget=bounded(a.get("memory_mb",1536),256,2560,"memory_mb")*1024*1024
    def monitor():
        parent=psutil.Process()
        while not stop.wait(.2):
            try:
                children=parent.children(recursive=True)
                rss=parent.memory_info().rss+sum(p.memory_info().rss for p in children if p.is_running())
                usage["peak"]=max(usage["peak"],rss)
                if rss>budget:
                    usage["exceeded"]=True
                    for child in children:
                        try:child.kill()
                        except psutil.Error:pass
                    return
            except psutil.Error:pass
    watcher=threading.Thread(target=monitor,daemon=True);watcher.start()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=executable,headless=True,chromium_sandbox=True)
            page=browser.new_page(viewport={"width":1280,"height":800},ignore_https_errors=False)
            def route_request(route):
                request_url=route.request.url
                if request_url.startswith(("data:","blob:","about:")) or origin(request_url) in allowed:route.continue_()
                else:
                    if len(blocked)<32:blocked.append(request_url)
                    route.abort()
            page.route("**/*",route_request)
            response=page.goto(url,wait_until="domcontentloaded",timeout=20000)
            title=page.title();final=page.url
            page.screenshot(path=str(path),full_page=True,timeout=20000)
            browser.close()
    finally:
        stop.set();watcher.join(1)
    if usage["exceeded"]:raise RuntimeError("browser job memory budget exceeded")
    return {"artifact":"work/"+name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
            "title":title,"url":final,"status_code":response.status if response else None,
            "image_kind":"real Chromium screenshot in Kali","peak_rss_bytes":usage["peak"],"chromium_sandbox":True,
            "blocked_external_requests":blocked}


def pwn_elf(a):
    from pwnlib.elf.elf import ELF
    elf=ELF(str(file_path(a)),checksec=False)
    return {"arch":elf.arch,"bits":elf.bits,"endian":elf.endian,"entry":elf.entry,
            "pie":elf.pie,"nx":elf.nx,"canary":elf.canary,"relro":elf.relro,
            "symbols":dict(list(elf.symbols.items())[:160]),"address_kind":"file virtual addresses; runtime ASLR not applied"}


def pwn_cyclic(a):
    from pwnlib.util.cyclic import cyclic
    n=bounded(a.get("n",4),4,8,"n")
    if n not in (4,8):raise ValueError("n must be 4 or 8")
    action=a.get("action","generate")
    if action=="generate":
        data=cyclic(bounded(a.get("length",64),1,4096,"length"),n=n)
        return {"pattern":data.decode("ascii"),"hex":data.hex(),"n":n}
    if action!="find":raise ValueError("action must be generate/find")
    value=a["value"]
    if isinstance(value,str):value=hexbytes(value,"value")
    if not isinstance(value,(bytes,int)) or isinstance(value,bool):raise ValueError("value must be hex text or an integer")
    if isinstance(value,bytes) and len(value)!=n:raise ValueError("value length must match n")
    if isinstance(value,int):value=value.to_bytes(n,"little",signed=False)
    maximum=bounded(a.get("max_length",4096),n,65536,"max_length")
    offset=cyclic(maximum,n=n).find(value)
    return {"offset":offset,"n":n,"search_limit":maximum,"found_within_limit":offset>=0,
            "note":"finite search for supplied observation; no target crash was executed"}


def pwn_rop(a):
    exe=Path(sys.executable).parent/"ROPgadget"
    if not exe.is_file():raise RuntimeError("ROPgadget missing in specialist environment")
    result=command([str(exe),"--binary",str(file_path(a)),"--depth",str(bounded(a.get("depth",6),2,20,"depth"))],30)
    if result["returncode"]:return dict(result,ok=False,error="ROPgadget failed")
    lines=result["stdout"].splitlines()
    pattern=a.get("query","")
    if pattern:lines=[line for line in lines if str(pattern).lower() in line.lower()]
    return dict(result,matching_lines=lines[:100],matches_truncated=len(lines)>100)


def reverse_binary(a):
    import lief
    binary=lief.parse(str(file_path(a)))
    if binary is None:raise ValueError("LIEF could not parse this binary")
    return {"format":str(binary.format),"entrypoint":binary.entrypoint,"imagebase":binary.imagebase,
            "sections":[{"name":s.name,"virtual_address":s.virtual_address,"offset":s.offset,"size":s.size} for s in binary.sections][:128],
            "imports":[getattr(x,"name",str(x)) for x in binary.imported_functions][:128],
            "address_kind":"file metadata; runtime ASLR not applied"}


def reverse_disassemble(a):
    import capstone
    arch=a.get("arch","x64")
    modes={"x86":(capstone.CS_ARCH_X86,capstone.CS_MODE_32),"x64":(capstone.CS_ARCH_X86,capstone.CS_MODE_64),
           "arm":(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM),"arm64":(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)}
    if arch not in modes:raise ValueError("arch must be x86/x64/arm/arm64")
    address=int(a.get("address",0))
    if a.get("code_hex") is not None:data=hexbytes(a["code_hex"],"code_hex")
    else:
        path=file_path(a);offset=bounded(a.get("offset",0),0,path.stat().st_size,"offset")
        with path.open("rb") as stream:stream.seek(offset);data=stream.read(bounded(a.get("size",128),1,16384,"size"))
    limit=bounded(a.get("limit",64),1,512,"limit")
    md=capstone.Cs(*modes[arch])
    lines=[]
    for i,ins in enumerate(md.disasm(data,address)):
        if i>=limit:break
        lines.append({"address":ins.address,"bytes":ins.bytes.hex(),"mnemonic":ins.mnemonic,"operands":ins.op_str})
    return {"arch":arch,"instructions":lines,"address_kind":"caller-supplied/file address; runtime ASLR not applied"}


def reverse_symbolic(a):
    import angr
    import claripy
    length=bounded(a.get("stdin_length",4),1,32,"stdin_length")
    steps=bounded(a.get("max_steps",200),1,2000,"max_steps")
    find=a.get("find_addresses",[]);avoid=a.get("avoid_addresses",[]);text=a.get("find_text")
    if not find and not text:raise ValueError("provide find_addresses or find_text")
    for seq in (find,avoid):
        if not isinstance(seq,list) or len(seq)>16 or not all(isinstance(v,int) and not isinstance(v,bool) for v in seq):raise ValueError("address lists must contain at most 16 integers")
    project=angr.Project(str(file_path(a)),auto_load_libs=False)
    symbolic=claripy.BVS("stdin",8*length)
    state=project.factory.full_init_state(stdin=angr.SimFileStream(name="stdin",content=symbolic,has_end=True))
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    if a.get("printable") is not False:
        for ch in symbolic.chop(8):state.solver.add(ch>=32,ch<=126)
    manager=project.factory.simulation_manager(state)
    target=(lambda s: str(text).encode() in s.posix.dumps(1)) if text else find
    for _ in range(steps):
        manager.explore(find=target,avoid=avoid,num_find=1,n=1)
        if manager.found or not manager.active:break
        if len(manager.active)>128:raise RuntimeError("symbolic state limit exceeded")
    if not manager.found:return {"found":False,"max_steps":steps,"active_states":len(manager.active),"candidate_verified":False}
    found=manager.found[0]
    candidate=found.solver.eval(symbolic,cast_to=bytes)
    return {"found":True,"candidate_hex":candidate.hex(),"stdout":found.posix.dumps(1).decode("utf-8","replace"),
            "candidate_verified":False,"note":"symbolic candidate only; replay in challenge VM before treating it as a solution"}


def crypto_factor(a):
    from sympy import factorint,isprime
    value=int(a["number"])
    if value<2 or value.bit_length()>4096:raise ValueError("number must be a positive integer of at most 4096 bits")
    factors=factorint(value,limit=bounded(a.get("limit",10000),1,1000000,"limit"))
    product=math.prod(int(p)**int(k) for p,k in factors.items())
    return {"factors":{str(p):int(k) for p,k in factors.items()},"product_matches":product==value,
            "complete":all(bool(isprime(p)) for p in factors)}


def crypto_crt(a):
    from sympy.ntheory.modular import crt
    moduli=a["moduli"];values=a["values"]
    if not isinstance(moduli,list) or not isinstance(values,list) or not 1<=len(moduli)<=64 or len(moduli)!=len(values):raise ValueError("provide equally sized moduli/values lists")
    moduli=[int(x) for x in moduli];values=[int(x) for x in values]
    if any(x<=0 or x.bit_length()>4096 for x in moduli):raise ValueError("moduli must be positive and bounded")
    result=crt(moduli,values,check=True)
    if result is None:raise ValueError("congruences are inconsistent")
    value,modulus=map(int,result)
    return {"value":value,"modulus":modulus,"verified":all(value%m==v%m for m,v in zip(moduli,values))}


def z3_expression(node,variables,z3):
    if isinstance(node,ast.Expression):return z3_expression(node.body,variables,z3)
    if isinstance(node,ast.Name) and node.id in variables:return variables[node.id]
    if isinstance(node,ast.Constant) and isinstance(node.value,(int,bool)) and (isinstance(node.value,bool) or node.value.bit_length()<=4096):return node.value
    if isinstance(node,ast.BinOp):
        left=z3_expression(node.left,variables,z3);right=z3_expression(node.right,variables,z3)
        ops={ast.Add:lambda:left+right,ast.Sub:lambda:left-right,ast.Mult:lambda:left*right,ast.Mod:lambda:left%right,
             ast.BitXor:lambda:left^right,ast.BitAnd:lambda:left&right,ast.BitOr:lambda:left|right,
             ast.LShift:lambda:left<<right,ast.RShift:lambda:left>>right}
        if type(node.op) in ops:return ops[type(node.op)]()
    if isinstance(node,ast.UnaryOp):
        value=z3_expression(node.operand,variables,z3)
        if isinstance(node.op,ast.USub):return -value
        if isinstance(node.op,ast.Invert):return ~value
        if isinstance(node.op,ast.Not):return z3.Not(value)
    if isinstance(node,ast.BoolOp):
        values=[z3_expression(x,variables,z3) for x in node.values]
        if isinstance(node.op,ast.And):return z3.And(*values)
        if isinstance(node.op,ast.Or):return z3.Or(*values)
    if isinstance(node,ast.Compare) and len(node.ops)==1:
        left=z3_expression(node.left,variables,z3);right=z3_expression(node.comparators[0],variables,z3)
        ops={ast.Eq:lambda:left==right,ast.NotEq:lambda:left!=right,ast.Lt:lambda:left<right,
             ast.LtE:lambda:left<=right,ast.Gt:lambda:left>right,ast.GtE:lambda:left>=right}
        if type(node.ops[0]) in ops:return ops[type(node.ops[0])]()
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and not node.keywords:
        allowed={name:getattr(z3,name) for name in ("And","Or","Not","Xor","If","ULT","ULE","UGT","UGE","LShR")}
        if node.func.id in allowed:return allowed[node.func.id](*[z3_expression(x,variables,z3) for x in node.args])
    raise ValueError("unsupported constraint syntax; Python execution/attributes are not allowed")


def crypto_z3(a):
    import z3
    if a.get("smt2") is not None:
        text=a["smt2"]
        if not isinstance(text,str) or len(text)>32768:raise ValueError("SMT-LIB text limit is 32 KiB")
        solver=z3.Solver();solver.from_string(text)
        solver.set(timeout=bounded(a.get("solver_timeout_ms",5000),1,15000,"solver_timeout_ms"))
        result=solver.check();model={}
        if result==z3.sat:
            actual=solver.model()
            model={decl.name():str(actual[decl]) for decl in actual.decls()[:64]}
        return {"status":str(result),"model":model,"format":"SMT-LIB2",
                "reason_unknown":solver.reason_unknown() if result==z3.unknown else None}
    spec=a["variables"];constraints=a["constraints"]
    if not isinstance(spec,dict) or not 1<=len(spec)<=32 or not isinstance(constraints,list) or len(constraints)>128:raise ValueError("bounded variables/constraints required")
    variables={}
    for name,kind in spec.items():
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}",name):raise ValueError("invalid variable name")
        if kind=="int":variables[name]=z3.Int(name)
        elif kind=="bool":variables[name]=z3.Bool(name)
        elif isinstance(kind,int) and not isinstance(kind,bool):variables[name]=z3.BitVec(name,bounded(kind,1,256,"bit width"))
        else:raise ValueError("variable type must be int/bool/bit width")
    solver=z3.Solver();solver.set(timeout=bounded(a.get("solver_timeout_ms",5000),1,15000,"solver_timeout_ms"))
    for text in constraints:
        if not isinstance(text,str) or len(text)>2000:raise ValueError("constraint text is too large")
        tree=ast.parse(text,mode="eval")
        if sum(1 for _ in ast.walk(tree))>512:raise ValueError("constraint AST too large")
        solver.add(z3_expression(tree,variables,z3))
    result=solver.check()
    model={}
    if result==z3.sat:
        actual=solver.model()
        for name,var in variables.items():
            value=actual.eval(var,model_completion=True)
            model[name]=z3.is_true(value) if z3.is_bool(value) else value.as_long()
    return {"status":str(result),"model":model,"reason_unknown":solver.reason_unknown() if result==z3.unknown else None}


def crypto_lll(a):
    from fpylll import IntegerMatrix,LLL
    basis=a["basis"]
    if not isinstance(basis,list) or not 1<=len(basis)<=64 or not all(isinstance(row,list) for row in basis):raise ValueError("bounded rectangular integer matrix required")
    width=len(basis[0])
    if not 1<=width<=64 or any(len(row)!=width for row in basis):raise ValueError("basis must be rectangular")
    if not all(isinstance(v,int) and not isinstance(v,bool) and v.bit_length()<=4096 for row in basis for v in row):raise ValueError("basis entries must be bounded integers")
    matrix=IntegerMatrix.from_matrix(basis);transform=IntegerMatrix.identity(len(basis))
    LLL.reduction(matrix,U=transform)
    reduced=[[int(matrix[i,j]) for j in range(width)] for i in range(len(basis))]
    change=[[int(transform[i,j]) for j in range(len(basis))] for i in range(len(basis))]
    valid=all(sum(change[i][k]*basis[k][j] for k in range(len(basis)))==reduced[i][j] for i in range(len(basis)) for j in range(width))
    return {"reduced_basis":reduced,"unimodular_transform":change,"transform_verified":valid}


def crypto_aes(a):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    key=hexbytes(a["key_hex"],"key_hex");data=hexbytes(a["ciphertext_hex"],"ciphertext_hex")
    if len(key) not in (16,24,32):raise ValueError("AES key must be 16/24/32 bytes")
    mode=a.get("mode","CBC").upper()
    authenticated=False
    if mode=="CBC":cipher=AES.new(key,AES.MODE_CBC,iv=hexbytes(a["iv_hex"],"iv_hex"));plain=cipher.decrypt(data)
    elif mode=="ECB":plain=AES.new(key,AES.MODE_ECB).decrypt(data)
    elif mode=="GCM":
        cipher=AES.new(key,AES.MODE_GCM,nonce=hexbytes(a["nonce_hex"],"nonce_hex"))
        if a.get("aad_hex"):cipher.update(hexbytes(a["aad_hex"],"aad_hex"))
        plain=cipher.decrypt_and_verify(data,hexbytes(a["tag_hex"],"tag_hex"));authenticated=True
    else:raise ValueError("mode must be CBC/ECB/GCM")
    if a.get("unpad") is True:plain=unpad(plain,16)
    return {"plaintext_hex":plain.hex(),"plaintext_base64":base64.b64encode(plain).decode(),
            "text_preview":plain[:4096].decode("utf-8","replace"),"authenticated":authenticated}


def misc_file(a):
    path=file_path(a);digest=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1048576),b""):digest.update(chunk)
    with path.open("rb") as stream:sample=stream.read(1048576)
    counts=Counter(sample)
    entropy=-sum((n/len(sample))*math.log2(n/len(sample)) for n in counts.values()) if sample else 0
    strings=[{"offset":m.start(),"text":m.group().decode("ascii")} for m in re.finditer(rb"[\x20-\x7e]{4,}",sample)][:100]
    identification=command(["file","--",str(path)],15)
    return {"bytes":path.stat().st_size,"sha256":digest.hexdigest(),"magic_hex":sample[:32].hex(),
            "file":identification,"entropy_sample":entropy,"sample_bytes":len(sample),"strings":strings}


def misc_archive(a):
    path=file_path(a);items=[];truncated=False
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            all_items=archive.infolist();total=len(all_items)
            items=[{"name":x.filename,"size":x.file_size,"compressed":x.compress_size} for x in all_items[:2000]]
            truncated=total>2000
        kind="zip"
    elif tarfile.is_tarfile(path):
        with tarfile.open(path,"r:*") as archive:
            for i,x in enumerate(archive):
                if i>=2000:truncated=True;break
                items.append({"name":x.name,"size":x.size,"is_link":x.issym() or x.islnk()})
        total=None if truncated else len(items);kind="tar"
    else:return dict(command(["7z","l","-slt",str(path)],30),extracted=False,format="7z-compatible")
    unsafe=[x["name"] for x in items if x["name"].startswith(("/","\\")) or ".." in Path(x["name"].replace("\\","/")).parts]
    return {"format":kind,"members":items,"total_members":total,"truncated":truncated,"unsafe_member_paths":unsafe,"extracted":False}


def image_end(data,format):
    if format=="PNG":
        offset=8
        while offset+12<=len(data):
            size=int.from_bytes(data[offset:offset+4],"big");end=offset+size+12
            if end>len(data):break
            if data[offset+4:offset+8]==b"IEND":return end
            offset=end
    if format=="WEBP" and data[:4]==b"RIFF":return int.from_bytes(data[4:8],"little")+8
    if format=="JPEG":
        offset=data.rfind(b"\xff\xd9")
        if offset>=0:return offset+2
    return None


def misc_image(a):
    from PIL import Image
    path=file_path(a)
    if path.stat().st_size>64*1024*1024:raise ValueError("image inspection limit is 64 MiB")
    data=path.read_bytes()
    with Image.open(path) as image:
        if image.width*image.height>25000000:raise ValueError("image pixel limit exceeded")
        info={str(k):str(v)[:2000] for k,v in image.info.items() if not isinstance(v,bytes)}
        exif={str(k):str(v)[:1000] for k,v in image.getexif().items()}
        result={"format":image.format,"width":image.width,"height":image.height,"mode":image.mode,"metadata":info,"exif":exif}
        end=image_end(data,image.format)
    tail=data[end:] if end is not None and end<=len(data) else b""
    return dict(result,recognized_end=end,trailing_bytes=len(tail),trailing_hex_preview=tail[:512].hex(),
                note="metadata and format tail inspection; not a comprehensive steganography check")


def forensics_pcap(a):
    from scapy.all import PcapReader,IP,IPv6,TCP,UDP,DNS,Raw
    limit=bounded(a.get("max_packets",20000),1,100000,"max_packets")
    packets=0;protocols=Counter();flows=Counter();truncated=False;dns_questions=Counter();payload_samples=[]
    with PcapReader(str(file_path(a))) as reader:
        for packet in reader:
            if packets>=limit:truncated=True;break
            packets+=1
            net=packet.getlayer(IP) or packet.getlayer(IPv6)
            protocol="TCP" if TCP in packet else "UDP" if UDP in packet else packet.lastlayer().name
            protocols[protocol]+=1
            if net:
                layer=packet.getlayer(TCP) or packet.getlayer(UDP)
                flows[(str(net.src),str(net.dst),protocol,int(layer.sport) if layer else None,int(layer.dport) if layer else None)]+=1
            if DNS in packet:
                for question in packet[DNS].qd[:8]:
                    name=getattr(question,"qname",b"")
                    if isinstance(name,bytes) and name:dns_questions[name.decode("utf-8","replace")]+=1
            if Raw in packet and len(payload_samples)<8:
                data=bytes(packet[Raw].load)[:256]
                payload_samples.append({"packet":packets,"hex":data.hex(),"text":data.decode("utf-8","replace")})
    return {"packets_read":packets,"protocols":dict(protocols),"truncated":truncated,
            "flows":[{"src":k[0],"dst":k[1],"protocol":k[2],"sport":k[3],"dport":k[4],"packets":v} for k,v in flows.most_common(100)],
            "dns_questions":dict(dns_questions.most_common(100)),"payload_samples":payload_samples,"offline":True}


def forensics_volatility(a):
    exe=Path(sys.executable).parent/"vol"
    if not exe.is_file():raise RuntimeError("Volatility3 CLI missing")
    plugin=a.get("plugin","help")
    if plugin=="help":return dict(command([str(exe),"--offline","-h"],30),memory_image_analyzed=False)
    allowed={"windows.info.Info","windows.pslist.PsList","windows.pstree.PsTree","windows.netscan.NetScan",
             "linux.pslist.PsList","linux.bash.Bash","mac.pslist.PsList"}
    if plugin not in allowed:raise ValueError("plugin must be help or an explicitly supported plugin")
    result=command([str(exe),"--offline","-f",str(file_path(a)),plugin],90)
    if result["returncode"]:return dict(result,ok=False,error="Volatility3 failed; inspect missing layer/symbol requirements")
    return dict(result,memory_image_analyzed=True,plugin=plugin,offline=True)


OPS={"status":inspect_status,"web_html":web_html,"web_http":web_http,"web_jwt":web_jwt,"web_capture":web_capture,
     "pwn_elf":pwn_elf,"pwn_cyclic":pwn_cyclic,"pwn_rop":pwn_rop,
     "reverse_binary":reverse_binary,"reverse_disassemble":reverse_disassemble,"reverse_symbolic":reverse_symbolic,
     "crypto_factor":crypto_factor,"crypto_crt":crypto_crt,"crypto_z3":crypto_z3,"crypto_lll":crypto_lll,"crypto_aes":crypto_aes,
     "misc_file":misc_file,"misc_archive":misc_archive,"misc_image":misc_image,
     "forensics_pcap":forensics_pcap,"forensics_volatility":forensics_volatility}


def main():
    if len(sys.argv)!=2:raise ValueError("provide a request JSON file")
    path=Path(sys.argv[1])
    if path.stat().st_size>65536:raise ValueError("request limit is 64 KiB")
    request=json.loads(path.read_text(encoding="utf-8"))
    operation=request["operation"];args=request["args"]
    if operation not in OPS or not isinstance(args,dict):raise ValueError("unknown operation or arguments")
    import resource
    memory=bounded(args.get("memory_mb",1536),256,2560,"memory_mb")*1024*1024
    # Chromium reserves large virtual ranges; its job uses an RSS monitor instead.
    if operation!="web_capture":resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
    budget=bounded(args.get("_budget_seconds",60),1,600,"execution budget")
    resource.setrlimit(resource.RLIMIT_CPU,(budget+2,budget+3))
    return OPS[operation](args)


def cli():
    """Keep dependency diagnostics on stderr and emit exactly one JSON result."""
    try:
        # Some dependencies configure their logger with the active stdout during
        # import. Redirect before main imports them, retaining their warnings.
        with contextlib.redirect_stdout(sys.stderr):
            result=main()
        status=1 if result.get("ok") is False else 0
    except Exception as exc:
        result={"ok":False,"error":str(exc),"error_code":"dependency_missing" if isinstance(exc,ImportError) else "operation_failed"}
        status=1
    print(json.dumps(result,ensure_ascii=False,default=str))
    return status


if __name__=="__main__":
    sys.exit(cli())
