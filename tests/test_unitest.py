import infi.iscsiapi
from infi.vendata.integration_tests import TestCase
from infi.vendata.integration_tests.iscsi import setup_iscsi_network_interface_on_host, setup_iscsi_on_infinibox
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from unittest import SkipTest
from infi.os_info import get_platform_string
from time import sleep
from infi.iscsiapi import auth as iscsi_auth

# reduce urlib error
import requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

INBOUND_USERNAME = "chapuser"
INBOUND_SECRET = "chappass123467"
OUTBOUND_USERNAME = "chap_user2"
OUTBOUND_SECRET = "PASS-chap_8&1231"

class ISCSIapi_host_TestCase(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.skip_if_not_available()
        cls.system = cls.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        cls.system.purge()
        cls.system_sdk = cls.system.get_infinisdk()
        cls.system_sdk.login()
        cls.iscsiapi = infi.iscsiapi.get_iscsiapi()
        assert setup_iscsi_network_interface_on_host()
        if get_platform_string().startswith('solaris'):
            cls.clear_auth_on_initiator()

    def setUp(self):
        self.addCleanup(self._cleanup_iscsi_connections())

    def _cleanup_iscsi_connections(self):
        self.iscsiapi.undiscover()
        self.clear_auth_on_initiator()

    @classmethod
    def tearDownClass(cls):
        from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        try:
            purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        except:
            cls.system.purge()
        finally:
            cls.system.purge()
            cls.system.release()

    @classmethod
    def skip_if_not_available(cls):
        try:
            infi.iscsiapi.get_iscsiapi()
        except ImportError:
            raise SkipTest("not available on this platform")

    @classmethod
    def clear_auth_on_initiator(cls):
        '''temporery work around for discovery with chap'''
        if get_platform_string().startswith('solaris'):
            iscsi = infi.iscsiapi.get_iscsiapi()
            iscsi._set_auth(iscsi_auth.NoAuth(), "bla")

    def test_01_iscsi_software(self):
        iscsi_sw = infi.iscsiapi.get_iscsi_software_initiator()
        if get_platform_string().startswith('solaris'):
            raise SkipTest("iSCSI is installed by default on Solaris")
        if not iscsi_sw.is_installed():
            iscsi_sw.install()
            iscsi_sw.uninstall()
            iscsi_sw.install()
        self.assertNotEqual(iscsi_sw.is_installed, True)

    def test_02_iscsiapi_set_source_iqn(self):
        from infi.dtypes.iqn import IQN
        new_iqn_string = 'iqn.1991-05.com.microsoft:asdasd'
        original_iqn = self.iscsiapi.get_source_iqn()
        self.iscsiapi.set_source_iqn(new_iqn_string)
        self.assertEqual(type(self.iscsiapi.get_source_iqn()), IQN)
        self.assertEqual(str(self.iscsiapi.get_source_iqn()), new_iqn_string)
        self.iscsiapi.set_source_iqn(str(original_iqn))
        self.assertEqual(str(self.iscsiapi.get_source_iqn()), original_iqn)

    def test_03_discover_undiscover(self):
        self.iscsiapi.undiscover()
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        sleep(5)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        self.addCleanup(self.iscsiapi.logout_all, target)
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 1)
        self.assertEqual(type(target), infi.iscsiapi.base.Target)
        self.assertEqual(target.get_discovery_endpoint().get_ip_address(), net_space.get_field('ips')[0].ip_address)
        self.assertNotEqual(target.get_iqn(), None)
        self.assertEqual(self.iscsiapi.get_discovered_targets()[0].get_iqn(), target.get_iqn())
        self.iscsiapi.undiscover(target)
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)

    def _create_host(self, hostname):
        ibox = self.system_sdk
        host = ibox.hosts.create(name=hostname)
        host.add_port(address=self.iscsiapi.get_source_iqn())
        self.addCleanup(host.delete)
        return host

    def _change_auth_on_ibox(self, host, auth_type):
        from infi.iscsiapi import auth
        if isinstance(auth_type, auth.NoAuth):
            host.update_security_method('NONE')
        elif isinstance(auth_type, auth.ChapAuth):
            host.update_security_chap_inbound_username(auth_type.get_inbound_username())
            host.update_security_chap_inbound_secret(auth_type.get_inbound_secret())
            host.update_security_method('CHAP')
        elif isinstance(auth_type, auth.MutualChapAuth):
            host.update_security_chap_inbound_username(auth_type.get_inbound_username())
            host.update_security_chap_inbound_secret(auth_type.get_inbound_secret())
            host.update_security_chap_outbound_username(auth_type.get_outbound_username())
            host.update_security_chap_outbound_secret(auth_type.get_outbound_secret())
            host.update_security_method('MUTUAL_CHAP')
        security_method = host.get_field(field_name="security_method", from_cache=False)

    def _logout_and_verify(self, target):
        self.iscsiapi.logout_all(target)
        sessions = self.iscsiapi.get_sessions()
        self.assertEqual(len(sessions), 0)

    def _assert_discovery_login_logout(self, net_space, host, auth):
        self._change_auth_on_ibox(host, auth)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        self.addCleanup(self.iscsiapi.logout_all, target)

        sessions = self.iscsiapi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        self._logout_and_verify(target)

    def test_04_login_logout(self):
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        ibox = self.system_sdk
        host = self._create_host("iscsi_testing_host")
        auth = iscsi_auth.NoAuth()

        self._assert_discovery_login_logout(net_space, host, None)
        self._assert_discovery_login_logout(net_space, host, None)


    def test_05_chap_login(self):
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        ibox = self.system_sdk
        host = self._create_host("iscsi_testing_host")
        auth = iscsi_auth.ChapAuth(INBOUND_USERNAME, INBOUND_SECRET)

        self._assert_discovery_login_logout(net_space, host, auth)

        # discovery on solaris doesn't work now with chap
        if get_platform_string().startswith('solaris'):
            self.clear_auth_on_initiator()

        self._assert_discovery_login_logout(net_space, host, auth)

    def test_06_mutual_chap_login(self):
        if get_platform_string().startswith('solaris'):
            raise SkipTest("mutual chap does not work on solaris yet")
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        ibox = self.system_sdk
        host = self._create_host("iscsi_testing_host")
        auth = iscsi_auth.MutualChapAuth(INBOUND_USERNAME, INBOUND_SECRET, OUTBOUND_USERNAME, OUTBOUND_SECRET)

        self._assert_discovery_login_logout(net_space, host, auth)

        # discovery on solaris doesn't work now with chap
        if get_platform_string().startswith('solaris'):
            self.clear_auth_on_initiator()

        self._assert_discovery_login_logout(net_space, host, auth)
