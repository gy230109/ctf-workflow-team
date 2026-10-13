"""Deployment decisions and first-use SSH trust, without real installs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import ctf_team as team


class DeploymentTests(unittest.TestCase):
    def test_select_only_unique_kali(self):
        vms = [{"vmx": "other.vmx", "likely_kali": False}, {"vmx": "kali.vmx", "likely_kali": True}]
        self.assertEqual(team.select_vm(vms), "kali.vmx")

    def test_multiple_or_no_kali_requires_selection(self):
        for vms in ([], [{"vmx": "one", "likely_kali": False}], [{"vmx": "one", "likely_kali": True}, {"vmx": "two", "likely_kali": True}]):
            with self.assertRaises(ValueError):
                team.select_vm(vms)

    def test_existing_vm_is_not_restarted(self):
        with patch.object(team, "output", return_value="Total running VMs: 1\nselected.vmx"), patch.object(team, "run", return_value=subprocess.CompletedProcess([], 0, b"192.168.1.23\n", b"")) as calls:
            self.assertEqual(team.guest_address("vmrun", "selected.vmx", True), "192.168.1.23")
        self.assertNotIn("start", calls.call_args.args[0])

    def test_stopped_vm_is_not_started_without_flag(self):
        with patch.object(team, "output", return_value="Total running VMs: 0"), patch.object(team, "run") as calls:
            with self.assertRaises(ValueError):
                team.guest_address("vmrun", "selected.vmx", False)
        calls.assert_not_called()

    def test_missing_known_hosts_is_not_auto_trusted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(team, "run") as calls:
            self.assertIsNone(team.trusted_host("ssh-keygen", "192.168.1.23", Path(directory) / "missing"))
        calls.assert_not_called()

    def test_existing_host_pin_uses_keygen_not_keyscan(self):
        with tempfile.TemporaryDirectory() as directory:
            known = Path(directory) / "known_hosts"
            known.write_text("existing", encoding="utf-8")
            with patch.object(team, "run", return_value=subprocess.CompletedProcess([], 0, b"# comment\nhost ssh-ed25519 publicfixture\n", b"")) as calls:
                record = team.trusted_host("ssh-keygen", "host", known)
            self.assertIn("host ssh-ed25519", record)
            self.assertEqual(calls.call_args.args[0][1], "-F")

    def test_failed_subprocess_preserves_exit(self):
        with patch.object(team.subprocess, "run", return_value=subprocess.CompletedProcess([], 7, b"", b"actual error")):
            with self.assertRaisesRegex(RuntimeError, "actual error"):
                team.run(["fixture"])

    def test_guest_setup_no_unnecessary_pip_network(self):
        self.assertIn("venv", team.GUEST_INSTALL)
        self.assertNotIn("--break-system-packages", team.GUEST_INSTALL)
        self.assertNotIn("StrictHostKeyChecking=no", team.GUEST_INSTALL)


if __name__ == "__main__":
    unittest.main()
