"""Synthetic export-budget/cleanup checks; no contest captures or TShark needed."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import zipfile


ROOT=Path(__file__).resolve().parents[1]


class PcapWorkerTests(unittest.TestCase):
    def setUp(self):
        # Keep test artifacts beside the checkout, including on Windows hosts.
        self.temp=tempfile.TemporaryDirectory(prefix='pcap-worker-test-',dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.case=Path(self.temp.name)
        self.work=self.case/'work';self.work.mkdir()
        self.original=self.work/'original.pcap';self.original.write_bytes(b'original attachment')
        spec=importlib.util.spec_from_file_location('pcap_worker_under_test',ROOT/'tools'/'ctf_pcap_worker.py')
        self.worker=importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ,{'CTF_CASE_DIR':str(self.case)}):
            if os.name=='nt':
                with mock.patch.dict(sys.modules,{'resource':types.ModuleType('resource')}):
                    spec.loader.exec_module(self.worker)
            else:spec.loader.exec_module(self.worker)
        self.args={'target':'original.pcap','action':'http_objects'}

    def exporter(self,argv,timeout,export_folder=None):
        self.assertIsNotNone(export_folder)
        (export_folder/'hello.txt').write_bytes(b'hello')
        return '',False,''

    def test_success_retains_zip_and_removes_temporary_objects(self):
        with mock.patch.object(self.worker,'run',side_effect=self.exporter):result=self.worker.main(self.args)
        self.assertTrue(result['ok'])
        self.assertEqual(result['count'],1)
        self.assertFalse(any(p.is_dir() for p in self.work.glob('pcap-http-*')))
        with zipfile.ZipFile(self.case/result['artifact']) as archive:
            self.assertEqual(archive.read('objects/hello.txt'),b'hello')
        self.assertEqual(self.original.read_bytes(),b'original attachment')

    def test_export_failure_removes_objects_and_preserves_attachment(self):
        def failed(*args,export_folder,**kwargs):
            (export_folder/'partial').write_bytes(b'partial')
            raise ValueError('budget exceeded')
        with mock.patch.object(self.worker,'run',side_effect=failed):
            with self.assertRaisesRegex(ValueError,'budget exceeded'):self.worker.main(self.args)
        self.assertEqual(list(self.work.glob('pcap-http-*')),[])
        self.assertEqual(self.original.read_bytes(),b'original attachment')

    def test_failed_zip_is_removed(self):
        with mock.patch.object(self.worker,'run',side_effect=self.exporter):
            with mock.patch.object(zipfile.ZipFile,'writestr',side_effect=OSError('synthetic disk failure')):
                with self.assertRaisesRegex(OSError,'synthetic disk failure'):self.worker.main(self.args)
        self.assertEqual(list(self.work.glob('pcap-http-*')),[])

    def test_existing_zip_is_never_removed(self):
        token='0123456789ab';dest=self.work/f'pcap-http-{token}.zip'
        dest.write_bytes(b'existing artifact')
        with mock.patch.object(self.worker.uuid,'uuid4',return_value=types.SimpleNamespace(hex=token)):
            with mock.patch.object(self.worker,'run',side_effect=self.exporter):
                with self.assertRaises(FileExistsError):self.worker.main(self.args)
        self.assertEqual(dest.read_bytes(),b'existing artifact')
        self.assertFalse((self.work/f'pcap-http-{token}').exists())

    def test_aggregate_size_is_checked_across_individually_small_files(self):
        folder=self.work/'export';folder.mkdir()
        for name in ('one','two'):
            with (folder/name).open('wb') as output:output.truncate(9*1048576)
        with self.assertRaisesRegex(ValueError,'200 files / 16 MiB'):self.worker.http_export_files(folder)

    def test_cleanup_refuses_attachment_directory(self):
        with self.assertRaisesRegex(ValueError,'unexpected HTTP export directory'):
            self.worker.cleanup_http_export(self.work,'0123456789ab')
        self.assertTrue(self.original.exists())

    def test_runtime_budget_kills_process_group_before_writer_finishes(self):
        folder=self.work/'export';folder.mkdir()
        proc=mock.Mock(pid=123456,returncode=0)
        def wait(timeout=None):
            if timeout is not None:
                for n in range(201):(folder/str(n)).write_bytes(b'x')
                raise subprocess.TimeoutExpired('synthetic writer',timeout)
            return 0
        proc.wait.side_effect=wait
        with mock.patch.object(self.worker.subprocess,'Popen',return_value=proc):
            with mock.patch.object(self.worker.os,'killpg',create=True) as kill:
                with mock.patch.object(self.worker.signal,'SIGKILL',9,create=True):
                    with self.assertRaisesRegex(ValueError,'200 files / 16 MiB'):
                        self.worker.run(['synthetic-writer'],10,export_folder=folder)
        kill.assert_called_once_with(proc.pid,9)
        self.assertLessEqual(proc.wait.call_args_list[0].kwargs['timeout'],.1)

    def test_final_budget_check_catches_writer_that_exits_immediately(self):
        folder=self.work/'export';folder.mkdir()
        proc=mock.Mock(pid=123456,returncode=0)
        def wait(timeout=None):
            if timeout is not None:
                for n in range(201):(folder/str(n)).write_bytes(b'x')
            return 0
        proc.wait.side_effect=wait
        with mock.patch.object(self.worker.subprocess,'Popen',return_value=proc):
            with mock.patch.object(self.worker.os,'killpg',create=True):
                with mock.patch.object(self.worker.signal,'SIGKILL',9,create=True):
                    with self.assertRaisesRegex(ValueError,'200 files / 16 MiB'):
                        self.worker.run(['synthetic-writer'],10,export_folder=folder)

    @unittest.skipUnless(os.name=='posix','Real process-group termination requires Linux/POSIX')
    def test_linux_live_writer_is_killed_for_count_and_total_bytes(self):
        script='''import os,pathlib,sys,time
folder=pathlib.Path(sys.argv[1]);pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))
if sys.argv[3]=='count':
 for n in range(201):(folder/str(n)).write_bytes(b'x')
else:
 for n in range(2):
  with (folder/str(n)).open('wb') as f:f.truncate(9*1048576)
time.sleep(10)
'''
        for mode in ('count','bytes'):
            with self.subTest(mode=mode):
                folder=self.work/mode;folder.mkdir();pid_file=self.work/f'{mode}.pid'
                started=time.monotonic()
                with self.assertRaisesRegex(ValueError,'200 files / 16 MiB'):
                    self.worker.run([sys.executable,'-c',script,str(folder),str(pid_file),mode],5,export_folder=folder)
                self.assertLess(time.monotonic()-started,3)
                with self.assertRaises(ProcessLookupError):os.kill(int(pid_file.read_text()),0)


if __name__=='__main__':unittest.main()
