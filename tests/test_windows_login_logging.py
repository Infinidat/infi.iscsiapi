"""Exercise Windows command construction without native WMI/service dependencies."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

from infi.iscsiapi import auth, base


class WindowsLoginLoggingTests(unittest.TestCase):
    def test_mutual_chap_commands_use_secrets_without_logging_them(self):
        service = ModuleType("infi.win32service")
        service.ServiceControlManagerContext = Mock()
        wmi = ModuleType("infi.wmi")
        wmi.WmiClient = Mock()
        iqn = ModuleType("infi.dtypes.iqn")
        iqn.IQN = str
        source = Path(__file__).resolve().parents[1] / "src" / "infi" / "iscsiapi" / "windows.py"
        spec = importlib.util.spec_from_file_location("infi.iscsiapi._windows_login_test", source)
        windows = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {service.__name__: service, wmi.__name__: wmi, iqn.__name__: iqn}):
            spec.loader.exec_module(windows)

        api = windows.WindowsISCSIapi()
        api._initiator = base.Initiator("iqn.initiator", "ROOT\\ISCSIPRT\\0000_0")
        endpoint = base.Endpoint("192.0.2.1", 3260)
        target = base.Target([endpoint], endpoint, "iqn.target")
        credentials = auth.MutualChapAuth("forward-user", "forward-secret", "reverse-user", "reverse-secret")
        process = Mock()
        process.get_returncode.return_value = 0
        with patch.object(windows, "execute", return_value=process) as execute, patch.object(windows, "logger") as logger:
            for command in ("LoginTarget", "PersistentLoginTarget"):
                api._iscsicli_login(command, target, endpoint, credentials)
        self.assertEqual(execute.call_count, 4)
        self.assertEqual(execute.call_args_list[0].args[0], ["iscsicli", "CHAPSecret", "reverse-secret"])
        self.assertIn("forward-secret", execute.call_args_list[1].args[0])
        self.assertIn("forward-secret", execute.call_args_list[3].args[0])
        messages = " ".join(str(call) for call in logger.mock_calls)
        self.assertNotIn("forward-secret", messages)
        self.assertNotIn("reverse-secret", messages)
        self.assertNotIn("forward-user", messages)
        self.assertIn("iqn.target", messages)
