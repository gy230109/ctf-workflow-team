"""Release integrity and upgrade preservation using isolated installations."""
import hashlib,json
from pathlib import Path
import sys,tempfile,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'tools'))
import team_upgrade as upgrade
import install_skill as skills

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.source=self.base/'new';self.target=self.base/'old'
        self.source.mkdir();self.target.mkdir()
        self.contents={'tools/ctf_os.py':b'new code','README.md':b'new docs','AGENTS.md':b'new rules'}
        for n,b in self.contents.items():
            p=self.source/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        self.manifest={'version':'fixture','files':[{'path':n,'sha256':hashlib.sha256(b).hexdigest()} for n,b in self.contents.items()]}
        self.write_manifest()
    def write_manifest(self):
        (self.source/'bundle-manifest.json').write_text(json.dumps(self.manifest),encoding='utf-8')
    def test_apply_preserves_machine_state_and_keeps_code_backup(self):
        for name in ('config/ctf_os.json','bridge/config/kali.json','wp/cases/demo/raw.txt','.venv/marker'):
            p=self.target/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'keep local state')
        (self.target/'README.md').write_bytes(b'old docs')
        result=upgrade.apply(self.source,self.target)
        self.assertEqual((self.target/'README.md').read_bytes(),b'new docs')
        self.assertEqual((Path(result['backup'])/'README.md').read_bytes(),b'old docs')
        for name in ('config/ctf_os.json','bridge/config/kali.json','wp/cases/demo/raw.txt','.venv/marker'):
            self.assertEqual((self.target/name).read_bytes(),b'keep local state')
    def test_plan_has_no_writes(self):
        upgrade.apply(self.source,self.target,True)
        self.assertEqual(list(self.target.iterdir()),[])
    def test_corrupted_release_rejected_before_target_changes(self):
        (self.source/'README.md').write_bytes(b'tampered')
        with self.assertRaises(ValueError):upgrade.apply(self.source,self.target)
        self.assertEqual(list(self.target.iterdir()),[])
    def test_private_configs_and_traversal_never_in_release(self):
        for name in ('config/ctf_os.json','bridge/config/kali.json','../escape','logs/private.txt','ctf-questionbank/answers/x'):
            with self.subTest(name=name),self.assertRaises(ValueError):upgrade.managed_path(name)
    def test_failure_restores_previous_files(self):
        (self.target/'tools').mkdir();(self.target/'tools/ctf_os.py').write_bytes(b'old code')
        (self.target/'README.md').write_bytes(b'old docs')
        actual=Path.write_bytes
        def fail_once(path,data):
            if path==self.target/'README.md' and data==b'new docs':raise OSError('fixture disk error')
            return actual(path,data)
        with patch.object(Path,'write_bytes',fail_once),self.assertRaises(OSError):upgrade.apply(self.source,self.target)
        self.assertEqual((self.target/'tools/ctf_os.py').read_bytes(),b'old code')
        self.assertEqual((self.target/'README.md').read_bytes(),b'old docs')
    def test_duplicate_paths_rejected(self):
        self.manifest['files'].append(self.manifest['files'][0]);self.write_manifest()
        with self.assertRaises(ValueError):upgrade.release(self.source)

class TraeInstallTests(unittest.TestCase):
    def test_global_and_project_install_preserve_other_skill(self):
        with tempfile.TemporaryDirectory() as t:
            home=Path(t)/'user';project=Path(t)/'project';project.mkdir()
            other=project/'.trae/skills/other/SKILL.md';other.parent.mkdir(parents=True);other.write_text('keep')
            global_result=skills.install('trae',ROOT,home)
            project_result=skills.install('trae',ROOT,home,project)
            self.assertTrue(global_result['installed'][0]['files_verified'])
            self.assertTrue(project_result['installed'][0]['files_verified'])
            self.assertEqual(Path(project_result['installed'][0]['path']),project/'.trae/skills/ctf-team-workflow')
            self.assertEqual(other.read_text(),'keep')
            self.assertTrue((home/'.trae-cn/skills/ctf-team-workflow/references/solving.md').exists())
    def test_changed_project_skill_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as t:
            home=Path(t)/'user';project=Path(t)/'project';project.mkdir()
            result=skills.install('trae',ROOT,home,project)
            path=Path(result['installed'][0]['path'])/'SKILL.md';path.write_text('local edits')
            with self.assertRaises(ValueError):skills.install('trae',ROOT,home,project)
            self.assertEqual(path.read_text(),'local edits')
if __name__=='__main__':unittest.main()
