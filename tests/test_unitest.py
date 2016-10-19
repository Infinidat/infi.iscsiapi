import infi.iscsiapi
from infi.vendata.integration_tests import TestCase
from infi.vendata.integration_tests.iscsi import setup_iscsi_network_interface_on_host
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from unittest import SkipTest
from infi.os_info import get_platform_string
from time import sleep

# reduce urlib error
import requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

INBOUND_USERNAME = "chap_user"
INBOUND_SECRET = "chap_pass-1234"
OUTBOUND_USERNAME = "chap_user2"
if get_platform_string().startswith('windows'):
    iscsi = infi.iscsiapi.get_iscsiapi()
    OUTBOUND_USERNAME = str(iscsi.get_source_iqn())

OUTBOUND_SECRET = "PASS-chap_8&123123"

class ISCSIapi_host_TestCase(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.skip_if_not_available()
        cls.system = cls.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        cls.system.purge()
        cls.system_sdk = cls.system.get_infinisdk()
        assert setup_iscsi_network_interface_on_host()

    @classmethod
    def tearDownClass(cls):
        from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        try:
            purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        except:
            pass
        # cls.system.purge()
        cls.system.release()

    @classmethod
    def skip_if_not_available(cls):
        try:
            infi.iscsiapi.get_iscsiapi()
        except ImportError:
            raise SkipTest("not available on this platform")

    def test_01_iscsi_software(self):
        iscsi_sw = infi.iscsiapi.get_iscsi_software_initiator()
        if get_platform_string().startswith('solaris'):
            raise SkipTest("iSCSI is installed by default on Solaris")
        if not iscsi_sw.is_installed():
            iscsi_sw.install()
            iscsi_sw.uninstall()
            iscsi_sw.install()
        self.assertNotEqual(iscsi_sw.is_installed, True)

    def test_iscsiapi_set_source_iqn(self):
        from infi.dtypes.iqn import IQN
        new_iqn_string = 'iqn.1991-05.com.microsoft:asdasd'
        iscsi = infi.iscsiapi.get_iscsiapi()
        original_iqn = iscsi.get_source_iqn()
        iscsi.set_source_iqn(new_iqn_string)
        self.assertEqual(type(iscsi.get_source_iqn()), IQN)
        self.assertEqual(str(iscsi.get_source_iqn()), new_iqn_string)
        iscsi.set_source_iqn(str(original_iqn))
        self.assertEqual(str(iscsi.get_source_iqn()), original_iqn)

    def test_discover_undiscover(self):
        from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        iscsi = infi.iscsiapi.get_iscsiapi()
        iscsi.undiscover()
        self.assertEqual(len(iscsi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        sleep(5)
        target = iscsi.discover(net_space.get_field('ips')[0].ip_address)
        self.assertEqual(len(iscsi.get_discovered_targets()), 1)
        self.assertEqual(type(target), infi.iscsiapi.base.Target)
        self.assertEqual(target.get_discovery_endpoint().get_ip_address(), net_space.get_field('ips')[0].ip_address)
        self.assertNotEqual(target.get_iqn(), None)
        self.assertEqual(iscsi.get_discovered_targets()[0].get_iqn(), target.get_iqn())
        iscsi.undiscover(target)
        self.assertEqual(len(iscsi.get_discovered_targets()), 0)

    def test_login_logout(self):
        from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        from infi.iscsiapi import auth as iscsi_auth
        iscsi = infi.iscsiapi.get_iscsiapi()
        iscsi.undiscover()
        if iscsi.get_discovered_targets() != []:
            for target in iscsi.get_discovered_targets():
                iscsi.logout_all(target)
        auth = iscsi_auth.NoAuth()
        self.assertEqual(len(iscsi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = iscsi.discover(net_space.get_field('ips')[0].ip_address)
        sessions = iscsi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        iscsi.logout_all(target)
        sessions = iscsi.get_sessions()
        self.assertEqual(len(sessions), 0)

    def _create_host(self, hostname):
        iscsi = infi.iscsiapi.get_iscsiapi()
        ibox = self.system_sdk
        host = ibox.hosts.create(name=hostname)
        host.add_port(address=iscsi.get_source_iqn())
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

    def test_login_logout_with_auth(self):
        from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        from infi.iscsiapi import auth as iscsi_auth
        from infi.execute import ExecutionError
        iscsi = infi.iscsiapi.get_iscsiapi()
        iscsi.undiscover()
        if iscsi.get_discovered_targets() != []:
            for target in iscsi.get_discovered_targets():
                iscsi.logout_all(target)
        self.assertEqual(len(iscsi.get_discovered_targets()), 0)
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = iscsi.discover(net_space.get_field('ips')[0].ip_address)
        ibox = self.system_sdk
        ibox.login()
        host = self._create_host("iscsi_testing_host")
        self.assertEqual(str(self._change_auth_on_ibox(host, 'chap')), 'chap')
        auth = iscsi_auth.ChapAuth(INBOUND_USERNAME, INBOUND_SECRET)
        sessions = iscsi.login_all(target, auth)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        iscsi.logout_all(target)
        auth = iscsi_auth.NoAuth()
        if get_platform_string().startswith('linux'):
            try:
                iscsi.login_all(target, auth)
            except ExecutionError:
                pass
        sessions = iscsi.get_sessions(target=target)
        self.assertEqual(len(sessions), 0)
        if get_platform_string().startswith('windows') or\
           get_platform_string().startswith('solaris'):
            '''Due to mutual chap bug nothing to check here for now'''
            pass
        else:
            self.assertEqual(str(self._change_auth_on_ibox(host, 'mutual_chap')), 'mutual_chap')
            auth = iscsi_auth.MutualChapAuth(INBOUND_USERNAME, INBOUND_SECRET, OUTBOUND_USERNAME, OUTBOUND_SECRET)
            sessions = iscsi.login_all(target, auth)
            self.assertEqual(len(sessions), len(target.get_endpoints()))
            iscsi._set_auth(iscsi_auth.NoAuth())  # host cleanup
