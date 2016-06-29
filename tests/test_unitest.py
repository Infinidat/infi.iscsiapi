from infi.vendata.integration_tests import TestCase
from infi.vendata.integration_tests.iscsi import is_iscsi_nic_available, setup_iscsi_network_interface_on_host
from mock import patch, MagicMock, mock_open
from infi.execute import execute_assert_success
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from unittest import SkipTest
from infi.os_info import get_platform_string
import infi.iscsiapi

# reduce urlib error
import requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ISCSIapi_host_TestCase(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.skip_if_not_available()
        cls.system = cls.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        cls.system.purge()
        cls.system_sdk = cls.system.get_infinisdk()
        setup_iscsi_network_interface_on_host()

    @classmethod
    def tearDownClass(cls):
        from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        try:
            purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        except:
            pass
        cls.system.purge()
        cls.system.release()

    @classmethod
    def skip_if_not_available(cls):
        try:
            infi.iscsiapi.get_iscsiapi()
        except ImportError:
            raise SkipTest("not available on this platform")

    def test_01_iscsi_software(self):
        iscsi_sw = infi.iscsiapi.get_iscsi_software_initator()
        if not iscsi_sw.is_installed():
            iscsi_sw.install()
            iscsi_sw.uninstall()
            iscsi_sw.install()
        self.assertNotEqual(iscsi_sw.is_installed, True)

    def test_iscsiapi_set_source_iqn(self):
        import infi.dtypes.iqn
        new_iqn_string = 'iqn.1991-05.com.microsoft:asdasd'
        iscsi = infi.iscsiapi.get_iscsiapi()
        original_iqn = iscsi.get_source_iqn()
        iscsi.set_source_iqn(new_iqn_string)
        self.assertEqual(type(iscsi.get_source_iqn()), infi.dtypes.iqn.IQN)
        self.assertEqual(str(iscsi.get_source_iqn()), new_iqn_string)
        iscsi.set_source_iqn(str(original_iqn))
        self.assertEqual(str(iscsi.get_source_iqn()), original_iqn)

    def test_discover_undiscover(self):
        from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        iscsi = infi.iscsiapi.get_iscsiapi()
        iscsi.undiscover()
        self.assertEqual(len(iscsi.get_discovered_targets()), 0 )
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = iscsi.discover(net_space.get_field('ips')[0].ip_address)
        self.assertEqual(len(iscsi.get_discovered_targets()), 1 )
        self.assertEqual(type(target), infi.iscsiapi.base.Target )
        self.assertEqual(target.get_discovery_endpoint().get_ip_address(),net_space.get_field('ips')[0].ip_address)
        self.assertNotEqual(target.get_iqn(), None )
        self.assertEqual(iscsi.get_discovered_targets()[0].get_iqn(), target.get_iqn())
        iscsi.undiscover(target)
        self.assertEqual(len(iscsi.get_discovered_targets()), 0 )

    def test_login_logout(self):
        from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        iscsi = infi.iscsiapi.get_iscsiapi()
        iscsi.undiscover()
        if iscsi.get_discovered_targets() != []:
            for target in iscsi.get_discovered_targets():
                iscsi.logout(target)
        self.assertEqual(len(iscsi.get_discovered_targets()), 0 )
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = iscsi.discover(net_space.get_field('ips')[0].ip_address)
        sessions = iscsi.login_all(target)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        iscsi.logout_all(target)
        sessions = iscsi.get_sessions()
        self.assertEqual(len(sessions), 0)
