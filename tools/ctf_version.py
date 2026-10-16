"""Team CTF workflow component. See README.md for configuration and verified scope."""
from datetime import datetime,timezone
import hashlib,json,os,sys
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
FILES=['ctf_os.py','ctf_os_runtime.py','ctf_mcp_server.py','ctf_rea.py','ctf_x64dbg.py','ctf_wp.py','ctf_crypto.py','ctf_knowledge.py','ctf_specialists.py','ctf_specialist_worker.py','ctf_reverse_route.py','ctf_jev.py','ctf_version.py']
FILES+=['ctf_pipeline.py','ctf_worker_gateway.py','ctf_worker_call.py','ctf_mcp_proxy.py']
FILES+=['ctf_extensions.py','ctf_extension_worker.py']
FILES+=['ctf_ctfd.py']
FILES+=['ctf_reference_sources.py']
FILES+=['ctf_cracktools.py']
FILES+=['ctf_wp_export.py','ctf_wp_assets.py','ctf_wp_windows.py']
FILES+=['ctf_pcap.py','ctf_pcap_worker.py','ctf_task_health.py']
FILES+=['ctf_wp_report.py','ctf_wp_review.py','ctf_wp_formats.py','ctf_product.py']
FILES+=['ctf_roles.py','ctf_product.py']

def fingerprint():
    records={name:hashlib.sha256((BASE/'tools'/name).read_bytes()).hexdigest() for name in FILES if (BASE/'tools'/name).is_file()}
    return hashlib.sha256(json.dumps(records,sort_keys=True).encode()).hexdigest()

LOADED_FINGERPRINT=fingerprint()
LOADED_AT=datetime.now(timezone.utc).isoformat()

def info(count):
    current=fingerprint()
    return {'release':'team-20261016-wp2','source_fingerprint':LOADED_FINGERPRINT,'disk_fingerprint':current,
        'reload_required':current!=LOADED_FINGERPRINT,'tool_count':count,'source_root':str(BASE),
        'python':sys.executable,'pid':os.getpid(),'loaded_at':LOADED_AT}
