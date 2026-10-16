"""Targeted checks for advisory telemetry; no actual challenges or model calls."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('health_under_test',ROOT/'tools/ctf_task_health.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


class HealthTests(unittest.TestCase):
    def setUp(self):
        directory=ROOT/'logs/health-test-temp';directory.mkdir(parents=True,exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=directory);self.previous=h.DB
        h.DB=Path(self.tmp.name)/'health.sqlite3'
    def tearDown(self):
        h.DB=self.previous;self.tmp.cleanup()
    def test_repeat_warns_without_blocking(self):
        for _ in range(3):value=h.observe('demo','math_gcd',{'values':[48,60]},{'ok':True,'result':12,'duration_ms':1})
        self.assertEqual(value['warnings'][0]['code'],'repeated_same_result')
        self.assertFalse(value['execution_blocked']);self.assertIsNone(value['model_cost'])
    def test_expected_repeats_are_not_loops(self):
        for _ in range(4):value=h.observe('demo','math_gcd',{'wp_repeat_expected':True},{'ok':True,'result':12})
        self.assertEqual(value['warnings'],[])
    def test_changed_file_breaks_signature(self):
        p=Path(self.tmp.name)/'input';p.write_text('old')
        for _ in range(2):h.observe('demo','read',{'local_file':str(p)},{'ok':True,'result':'same'})
        p.write_text('new');value=h.observe('demo','read',{'local_file':str(p)},{'ok':True,'result':'same'})
        self.assertEqual(value['warnings'],[])
    def test_failures_and_tasks_are_separate(self):
        for _ in range(3):value=h.observe('demo','read',{}, {'ok':False,'error_code':'missing'})
        self.assertIn('consecutive_failures',{x['code'] for x in value['warnings']})
        self.assertEqual(h.status({'case':'other'})['calls'],0)
    def test_different_results_are_not_stagnation(self):
        for n in range(4):value=h.observe('demo','read',{}, {'ok':True,'result':n})
        self.assertEqual(value['warnings'],[])
    def test_session_operations_are_expected(self):
        for _ in range(4):value=h.observe('demo','kali_debug_session',{'command':'-exec-next'},{'ok':True,'result':'running'})
        self.assertEqual(value['warnings'],[])
    def test_artifact_names_do_not_hide_same_result(self):
        for n in range(3):
            value=h.observe('demo','forensics_pcap',{'action':'summary'},
              {'ok':True,'result':{'data':{'packets':6,'artifact':str(n)},'execution':{'duration_seconds':n}}})
        self.assertEqual(value['warnings'][0]['code'],'repeated_same_result')


if __name__=='__main__':unittest.main()
