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

    @classmethod
    def tearDownClass(cls):
        from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        try:
            pass
            purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        except:
            pass
            cls.system.purge()
        finally:
            pass
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
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 1)
        self.assertEqual(type(target), infi.iscsiapi.base.Target)
        self.assertEqual(target.get_discovery_endpoint().get_ip_address(), net_space.get_field('ips')[0].ip_address)
        self.assertNotEqual(target.get_iqn(), None)
        self.assertEqual(self.iscsiapi.get_discovered_targets()[0].get_iqn(), target.get_iqn())
        self.iscsiapi.undiscover(target)
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)

    def test_04_login_logout(self):
        self.iscsiapi.undiscover()
        if self.iscsiapi.get_discovered_targets() != []:
            for target in self.iscsiapi.get_discovered_targets():
                self._logout_and_verify(target)
        auth = iscsi_auth.NoAuth()
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        sessions = self.iscsiapi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        self._logout_and_verify(target)

    def _create_host(self, hostname):
        ibox = self.system_sdk
        host = ibox.hosts.create(name=hostname)
        host.add_port(address=self.iscsiapi.get_source_iqn())
        return host

    def _change_auth_on_ibox(self, host, auth_type):
        if auth_type is None:
            host.update_security_method('none')
        elif auth_type == 'chap':
            host.update_security_chap_inbound_username(INBOUND_USERNAME)
            host.update_security_chap_inbound_secret(INBOUND_SECRET)
            host.update_security_method('chap')
        elif auth_type == 'mutual_chap':
            host.update_security_chap_inbound_username(INBOUND_USERNAME)
            host.update_security_chap_inbound_secret(INBOUND_SECRET)
            host.update_security_chap_outbound_username(OUTBOUND_USERNAME)
            host.update_security_chap_outbound_secret(OUTBOUND_SECRET)
            host.update_security_method('mutual_chap')
        security_method = host.get_field(field_name="security_method", from_cache=False)
        return str(security_method.lower())

    def _logout_and_verify(self, target):
        self.iscsiapi.logout_all(target)
        sessions = self.iscsiapi.get_sessions()
        self.assertEqual(len(sessions), 0)

    def test_05_chap_login_linux(self):
        if not get_platform_string().startswith('linux'):
            raise SkipTest("not available on this platform")
        self.iscsiapi.undiscover()
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        ibox = self.system_sdk
        host = self._create_host("iscsi_testing_host")
        self.assertEqual(str(self._change_auth_on_ibox(host, 'chap')), 'chap')
        auth = iscsi_auth.ChapAuth(INBOUND_USERNAME, INBOUND_SECRET)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        sessions = self.iscsiapi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        self._logout_and_verify(target)
        self.assertEqual(str(self._change_auth_on_ibox(host, 'mutual_chap')), 'mutual_chap')
        auth = iscsi_auth.MutualChapAuth(INBOUND_USERNAME, INBOUND_SECRET, OUTBOUND_USERNAME, OUTBOUND_SECRET)
        sessions = self.iscsiapi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))

    def test_06_chap_login_solaris(self):
        if not get_platform_string().startswith('solaris'):
            raise SkipTest("not available on this platform")
        self.iscsiapi.undiscover()
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        ibox = self.system_sdk
        host = self._create_host("iscsi_testing_host")
        self.assertEqual(str(self._change_auth_on_ibox(host, 'chap')), 'chap')
        self._logout_and_verify(target)
        auth = iscsi_auth.ChapAuth(INBOUND_USERNAME, INBOUND_SECRET)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        sessions = self.iscsiapi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        self.assertEqual(str(self._change_auth_on_ibox(host, 'mutual_chap')), 'mutual_chap')
        auth = iscsi_auth.MutualChapAuth(INBOUND_USERNAME, INBOUND_SECRET, OUTBOUND_USERNAME, OUTBOUND_SECRET)
        sessions = self.iscsiapi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
