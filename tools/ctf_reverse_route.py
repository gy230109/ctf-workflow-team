"""Team CTF workflow component. See README.md for configuration and verified scope."""
import hashlib
from pathlib import Path
import struct
import zipfile

BRANCHES = {
    'pe-native': {'platform':'Windows native x86/x64 PE', 'static_tools':['rea_status','rea_ops','rea_run'],
        'first_call':{'tool':'rea_run','args':{'command':'inspect','args':['{artifact}'],'timeout':300}},
        'followup':{'tool':'rea_run','args':{'command':'function','args':['{artifact}','{file_va}'],'timeout':300}},
        'dynamic_tools':['win_debug_status','win_debug_tools','win_debug_call'],
        'notes':['REA Windows provider is experimental; inspect actual availability first.', 'RVA=file_VA-ImageBase; runtime_VA=actual_module_base+RVA.']},
    'pe-managed': {'platform':'.NET PE', 'static_tools':['rea_ops','rea_run'],
        'first_call':{'tool':'rea_run','args':{'command':'inspect-managed-members','args':['{artifact}'],'timeout':180}},
        'dynamic_tools':[], 'notes':['Start with managed members; native boundaries require separate evidence.']},
    'elf': {'platform':'Linux ELF','static_tools':['reverse_binary_info','kali_objdump','reverse_disassemble'],
        'dynamic_tools':['kali_debug_session','qemu_run','reverse_symbolic','kali_run'], 'notes':['Use Kali Pwndbg/GDB sessions for ELF; non-native CPU requires matching QEMU and runtime libraries. Do not route ELF to Windows REA provider.']},
    'android': {'platform':'Android APK/DEX','static_tools':['kali_jadx','rea_ops','rea_run'],
        'dynamic_tools':[], 'notes':['REA Android operations require actual capability checks; use Kali jadx first.']},
    'source': {'platform':'source/script','static_tools':['misc_file_inspect'], 'dynamic_tools':['kali_run'],
        'notes':['Read the supplied source and verify in the challenge environment.']},
    'unknown': {'platform':'unclassified','static_tools':['misc_file_inspect','reverse_binary_info'],
        'dynamic_tools':[], 'notes':['Identify the format first; do not execute unknown artifacts automatically.']},
}

def identify(path):
    p=Path(path).resolve(strict=True)
    if not p.is_file():raise ValueError('local_file must be a regular artifact')
    with p.open('rb') as f:
        data=f.read(4096)
        subtype='unknown';details={}
        if data.startswith(b'\x7fELF'):
            if len(data)<20 or data[4] not in (1,2) or data[5] not in (1,2):raise ValueError('invalid ELF header')
            subtype='elf';machine=struct.unpack_from('<H' if data[5]==1 else '>H',data,18)[0]
            details={'architecture':{3:'x86',62:'x86_64',40:'arm',183:'aarch64',243:'riscv'}.get(machine,'unknown'),
                     'machine':machine,'bits':32 if data[4]==1 else 64,'endianness':'little' if data[5]==1 else 'big',
                     'execution_requirement':'Match guest architecture and ELF interpreter before executing; otherwise use a separately verified compatible environment.'}
        elif data.startswith(b'dex\n'):subtype='android'
        elif data.startswith(b'MZ') and len(data)>=64:
            pe=struct.unpack_from('<I',data,60)[0]
            if pe>p.stat().st_size-26:raise ValueError('invalid PE header offset')
            f.seek(pe);header=f.read(264)
            if header[:4]!=b'PE\x00\x00':raise ValueError('invalid PE signature')
            magic=struct.unpack_from('<H',header,24)[0]
            directory=24+(112 if magic==0x20b else 96 if magic==0x10b else 0)
            if directory==24:raise ValueError('unsupported PE optional header')
            clr=directory+14*8
            subtype='pe-managed' if len(header)>=clr+8 and struct.unpack_from('<II',header,clr)[0] else 'pe-native'
        elif p.suffix.lower()=='.apk' and zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                if 'AndroidManifest.xml' in z.namelist():subtype='android'
        elif p.suffix.lower() in {'.py','.c','.cc','.cpp','.js','.java','.rs','.go','.cs','.sh'} and b'\0' not in data:subtype='source'
        f.seek(0);digest=hashlib.file_digest(f,'sha256').hexdigest()
    return {'subtype':subtype,'artifact':str(p),'sha256':digest,'bytes':p.stat().st_size,**details}

def route(args):
    requested=args.get('subtype')
    if requested and requested not in BRANCHES:raise ValueError('subtype must be '+','.join(BRANCHES))
    fact=identify(args['local_file']) if args.get('local_file') else {'subtype':requested or 'unknown'}
    if requested and requested!=fact['subtype']:raise ValueError('requested subtype contradicts artifact header')
    selected=fact['subtype']
    return {'routing_version':'reverse-20261014','identification':fact,'selected':selected,
            'plan':BRANCHES[selected],'branches':BRANCHES,
            'verification':{'required':True,'method':'Run candidate through the real challenge program or authorized judge; record rejection too.'},
            'automatic_execution':False}
