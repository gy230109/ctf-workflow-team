"""Protocol failures, challenge separation and bounded execution, without network."""
import ast
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch,Mock

sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'tools'))
import ctf_os
import ctf_specialists as adapters
import ctf_specialist_worker as worker


class SpecialistContracts(unittest.TestCase):
    def test_cross_case_rejected_before_transport(self):
        with patch.object(adapters.runtime,'bridge_call') as bridge:
            with self.assertRaises(ValueError):adapters.execute('status',{'case':'one','wp_case':'two'})
        bridge.assert_not_called()

    def test_dangerous_operations_refuse_missing_confirmation(self):
        with patch.object(adapters.runtime,'bridge_call') as bridge:
            for name in adapters.DANGEROUS:
                result=ctf_os.call_tool(name,{})
                self.assertEqual(result['error_code'],'confirmation_required')
        bridge.assert_not_called()

    def test_request_and_worker_are_uploaded_and_hash_verified(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(adapters,'BASE',Path(directory)),patch.object(adapters,'settings',return_value={'enabled':True,'python':'/fixture/venv/bin/python3'}),patch.object(adapters.runtime,'bridge_call',return_value={'verified':True}) as upload,patch.object(adapters.runtime,'kali_execute',return_value={'returncode':0,'stdout':'{"value":23}'}) as run:
            result=adapters.execute('crypto_crt',{'case':'fixture','moduli':[3,5,7],'values':[2,3,2]})
            self.assertTrue(result['ok'])
            args=upload.call_args.args[0]
            self.assertEqual(args[:2],['put','fixture'])
            requests=[Path(p) for p in args[2:] if p.endswith('.json')]
            self.assertEqual(len(requests),1)
            body=json.loads(requests[0].read_text())
            self.assertEqual(body['args']['moduli'],[3,5,7])
            self.assertEqual(run.call_args.args[1][0],'/fixture/venv/bin/python3')

    def test_failed_upload_does_not_execute(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(adapters,'BASE',Path(directory)),patch.object(adapters,'settings',return_value={'enabled':True,'python':'/fixture/venv/bin/python3'}),patch.object(adapters.runtime,'bridge_call',return_value={'verified':False}),patch.object(adapters.runtime,'kali_execute') as run:
            self.assertFalse(adapters.execute('status',{'case':'fixture'})['ok'])
        run.assert_not_called()

    def test_guest_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(adapters,'BASE',Path(directory)),patch.object(adapters,'settings',return_value={'enabled':True,'python':'/fixture/venv/bin/python3'}),patch.object(adapters.runtime,'bridge_call',return_value={'verified':True}),patch.object(adapters.runtime,'kali_execute',return_value={'returncode':1,'stdout':'{"ok":false,"error":"actual failure"}' }):
            r=adapters.execute('status',{'case':'fixture'})
            self.assertFalse(r['ok']);self.assertEqual(r['error'],'actual failure')

    def test_non_json_guest_output_is_explicit_failure(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(adapters,'BASE',Path(directory)),patch.object(adapters,'settings',return_value={'enabled':True,'python':'/fixture/venv/bin/python3'}),patch.object(adapters.runtime,'bridge_call',return_value={'verified':True}),patch.object(adapters.runtime,'kali_execute',return_value={'returncode':0,'stdout':'not json'}):
            self.assertEqual(adapters.execute('status',{'case':'fixture'})['error_code'],'worker_failed')

    def test_json_array_is_not_a_valid_worker_result(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(adapters,'BASE',Path(directory)),patch.object(adapters,'settings',return_value={'enabled':True,'python':'/fixture/venv/bin/python3'}),patch.object(adapters.runtime,'bridge_call',return_value={'verified':True}),patch.object(adapters.runtime,'kali_execute',return_value={'returncode':0,'stdout':'[]'}):
            self.assertEqual(adapters.execute('status',{'case':'fixture'})['error_code'],'invalid_worker_response')

    def test_screenshot_claim_must_match_downloaded_hash(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(adapters,'BASE',Path(directory)),patch.object(adapters,'settings',return_value={'enabled':True,'python':'/fixture/venv/bin/python3'}),patch.object(adapters.runtime,'bridge_call',side_effect=[{'verified':True},{'verified':True,'sha256':'actual'}]),patch.object(adapters.runtime,'kali_execute',return_value={'returncode':0,'stdout':'{"artifact":"work/screen.png","sha256":"wrong"}'}),patch.object(adapters.wp,'capture') as capture:
            r=adapters.execute('web_capture',{'case':'fixture','wp_case':'fixture'})
            self.assertFalse(r['ok']);self.assertEqual(r['error_code'],'artifact_fetch_failed')
        capture.assert_not_called()

    def test_worker_cannot_open_other_challenge_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);case=root/'case';case.mkdir();file=root/'private.txt';file.write_text('private')
            with patch.dict(worker.os.environ,{'CTF_CASE_DIR':str(case)}):
                with self.assertRaises(ValueError):worker.file_path({'target':str(file)})

    def test_archive_listing_never_extracts_traversal_members(self):
        import zipfile
        with tempfile.TemporaryDirectory() as directory:
            case=Path(directory);archive=case/'unsafe.zip'
            with zipfile.ZipFile(archive,'w') as z:z.writestr('../outside.txt','fixture')
            with patch.dict(worker.os.environ,{'CTF_CASE_DIR':str(case)}):r=worker.misc_archive({'target':str(archive)})
            self.assertFalse(r['extracted']);self.assertEqual(r['unsafe_member_paths'],['../outside.txt'])
            self.assertFalse((case.parent/'outside.txt').exists())

    def test_z3_grammar_rejects_python_execution(self):
        for expression in ["__import__('os').system('command')","x.__class__","[x for x in [1]]"]:
            with self.assertRaises(ValueError):worker.z3_expression(ast.parse(expression,mode='eval'),{'x':1},object())

    def test_http_body_is_bounded_when_size_is_unknown(self):
        response=Mock();response.url='http://fixture.invalid/';response.status_code=200;response.headers={};response.encoding='utf-8'
        response.iter_content.return_value=iter([b'a'*65536]*20)
        with patch.dict(sys.modules,{'requests':types.SimpleNamespace(get=Mock(return_value=response))}):
            result=worker.web_http({'url':'http://fixture.invalid/','confirm':True})
        self.assertEqual(result['sample_bytes'],262144)
        response.close.assert_called_once()
        self.assertEqual(next(response.iter_content.return_value),b'a'*65536)

    def test_jwt_decoding_does_not_claim_signature_validation(self):
        r=worker.web_jwt({'token':'eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.'})
        self.assertFalse(r['signature_verified']);self.assertEqual(r['payload']['sub'],'fixture')

    def test_failed_specialist_is_retained_in_wp(self):
        import ctf_wp as wp
        with tempfile.TemporaryDirectory() as directory,patch.object(wp,'ROOT',Path(directory)):
            wp.init({'case':'fixture','title':'test'})
            fn,desc,schema=ctf_os.ALL_TOOLS['ctf_specialist_status']
            with patch.dict(ctf_os.ALL_TOOLS,{'ctf_specialist_status':(lambda a:{'ok':False,'error':'dependency unavailable'},desc,schema)}):
                r=ctf_os.call_tool('ctf_specialist_status',{'wp_case':'fixture'})
            self.assertFalse(r['ok']);self.assertIn('wp_record',r)
            rows=wp.records(Path(directory)/'fixture')
            self.assertEqual(rows[-1]['kind'],'call')


if __name__=='__main__':unittest.main()
