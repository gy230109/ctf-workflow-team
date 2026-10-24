"""Regression checks for the real specialist stdout framing failure."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('worker_under_test',ROOT/'tools/ctf_specialist_worker.py')
worker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class WorkerProtocol(unittest.TestCase):
    def run_cli(self,operation):
        stdout,stderr=io.StringIO(),io.StringIO()
        with patch.object(worker,'main',side_effect=operation),contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            code=worker.cli()
        return code,json.loads(stdout.getvalue()),stderr.getvalue(),stdout.getvalue()

    def test_dependency_warning_does_not_invalidate_json(self):
        def noisy():
            print('[!] Could not populate PLT: Cannot allocate 1GB memory to run Unicorn Engine')
            print('dependency diagnostic on stderr',file=sys.stderr)
            return {'arch':'amd64','bits':64,'symbols':{'main':4196038}}
        code,data,stderr,stdout=self.run_cli(noisy)
        self.assertEqual(code,0)
        self.assertEqual(data['arch'],'amd64')
        self.assertEqual(data['symbols']['main'],4196038)
        self.assertEqual(len(stdout.splitlines()),1)
        self.assertIn('Could not populate PLT',stderr)
        self.assertIn('dependency diagnostic on stderr',stderr)

    def test_import_failure_still_returns_error_and_nonzero_exit(self):
        def missing():
            print('dependency initialization warning')
            raise ImportError('pwntools unavailable')
        code,data,stderr,stdout=self.run_cli(missing)
        self.assertEqual(code,1)
        self.assertFalse(data['ok'])
        self.assertEqual(data['error_code'],'dependency_missing')
        self.assertEqual(data['error'],'pwntools unavailable')
        self.assertIn('initialization warning',stderr)
        self.assertEqual(len(stdout.splitlines()),1)

    def test_operation_failure_is_not_converted_to_success(self):
        def failed():
            print('operation warning')
            return {'ok':False,'error':'actual failure','error_code':'operation_failed'}
        code,data,stderr,_=self.run_cli(failed)
        self.assertEqual(code,1)
        self.assertFalse(data['ok'])
        self.assertEqual(data['error'],'actual failure')
        self.assertIn('operation warning',stderr)

    def test_raised_operation_failure_has_valid_error_json(self):
        def failed():
            print('before failure')
            raise ValueError('invalid request')
        code,data,stderr,_=self.run_cli(failed)
        self.assertEqual(code,1)
        self.assertEqual(data['error_code'],'operation_failed')
        self.assertEqual(data['error'],'invalid request')
        self.assertIn('before failure',stderr)

    def test_unicode_output_and_stdout_restoration(self):
        original=sys.stdout
        code,data,_,stdout=self.run_cli(lambda:{'message':'真实结果'})
        self.assertEqual(code,0)
        self.assertEqual(data['message'],'真实结果')
        self.assertIn('真实结果',stdout)
        self.assertIs(sys.stdout,original)


if __name__=='__main__':
    unittest.main()
