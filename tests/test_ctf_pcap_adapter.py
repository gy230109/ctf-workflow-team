"""Required PCAP evidence must fail closed; optional browser evidence stays separate."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import ctf_extensions as ext
import ctf_pcap


class AdapterTests(unittest.TestCase):
    def exercise(self,operation='pcap',valid=True,missing=False):
        folder=ROOT/'logs/pcap-adapter-tests';folder.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=folder) as d:
            p=Path(d)/'data.tsv';p.write_text('frame\tdata\n',encoding='utf-8')
            sha='a'*64
            data={'ok':True,'evidence_artifacts':[] if missing else [{'artifact':'work/data.tsv','sha256':sha,'kind':'data_export','source':'test'}]}
            fetch={'verified':valid,'sha256':sha,'local_path':str(p)}
            cfg=Path(d)/'extensions.json';cfg.write_text('{"enabled":false}',encoding='utf-8')
            with patch.object(ext,'CONFIG',cfg),patch.object(ext.runtime,'bridge_call',side_effect=[{'verified':True},fetch]) as bridge,patch.object(ext.runtime,'kali_execute',return_value={'stdout':json.dumps(data),'exit':0}) as run,patch.object(ext.specialists,'settings',side_effect=AssertionError('specialist venv must not be required')):
                value=ext.execute(operation,{'case':'pcap_test'},worker=ctf_pcap.WORKER,require_config=False,python='/usr/bin/python3')
                self.assertEqual(run.call_args.args[1][0],'/usr/bin/python3')
                return value
    def test_required_export_failure_is_error(self):
        r=self.exercise(valid=False);self.assertFalse(r['ok']);self.assertEqual(r['error_code'],'artifact_fetch_failed')
    def test_required_export_is_verified_without_extensions_enabled(self):
        r=self.exercise();self.assertTrue(r['ok']);self.assertEqual(len(r['evidence_artifacts']),1)
    def test_missing_primary_export_is_error(self):
        r=self.exercise(missing=True);self.assertFalse(r['ok']);self.assertEqual(r['error_code'],'artifact_fetch_failed')
    def test_browser_optional_capture_stays_independent(self):
        r=self.exercise(operation='browser',valid=False);self.assertTrue(r['ok']);self.assertEqual(len(r['capture_errors']),1)


if __name__=='__main__':unittest.main()
