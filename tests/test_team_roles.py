import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import ctf_roles
from ctf_product import Product

class Roles(unittest.TestCase):
    def test_live_role_reads_existing_files(self):
        result=ctf_roles.lookup(ROOT,member='B')
        self.assertTrue(result['ok']);self.assertEqual(result['primary'],'pwn')
        self.assertTrue(all(Path(x['local_path']).is_file() for x in result['reading']))
    def test_name_is_not_guessed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'team').mkdir();(root/'team/roles.json').write_bytes((ROOT/'team/roles.json').read_bytes())
            result=ctf_roles.lookup(root,name='Example Member')
            self.assertFalse(result['ok']);self.assertTrue(result['needs_identity'])
    def test_registration_is_local_and_restores_identity(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'team').mkdir();data=ctf_roles.definitions(ROOT)
            data['common_reading']=[]
            for event in data['profiles'].values():
                for member in event['members'].values():member['reading']=[]
            (root/'team/roles.json').write_text(json.dumps(data))
            ctf_roles.register(root,member='B',display_name='Example Member')
            result=ctf_roles.lookup(root,name='Example Member')
            self.assertEqual(result['primary'],'pwn');self.assertTrue((root/'.local/team-member.json').is_file())
            self.assertNotIn('Example Member',(root/'team/roles.json').read_text())
    def test_event_membership_is_explicit(self):
        self.assertFalse(ctf_roles.lookup(ROOT,member='C',profile='saturday-four')['ok'])
        self.assertEqual(ctf_roles.lookup(ROOT,member='C',profile='full-seven')['primary'],'web')
    def test_escaped_reading_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'team').mkdir();data=ctf_roles.definitions(ROOT);data['common_reading']=['../outside.md']
            (root/'team/roles.json').write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'outside'):ctf_roles.lookup(root,member='B')
    def test_product_role_dispatch(self):
        result=Product(ROOT).team_role(member='G')
        self.assertTrue(result['ok']);self.assertEqual(result['primary'],'crypto')
    def test_actual_stdio_role_tool(self):
        requests=[{'jsonrpc':'2.0','id':1,'method':'tools/list'},
                  {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'ctf_team_role','arguments':{'member':'B'}}}]
        run=subprocess.run([sys.executable,'-X','utf8',str(ROOT/'tools/ctf_entry.py'),'--stdio','--root',str(ROOT)],input=''.join(json.dumps(r)+'\n' for r in requests),capture_output=True,text=True,encoding='utf-8',timeout=30)
        self.assertEqual(run.returncode,0,run.stderr)
        responses=[json.loads(line) for line in run.stdout.splitlines()]
        self.assertIn('ctf_team_role',{t['name'] for t in responses[0]['result']['tools']})
        role=responses[1]['result']['structuredContent']
        self.assertTrue(role['ok']);self.assertEqual(role['primary'],'pwn')

if __name__=='__main__':unittest.main()
