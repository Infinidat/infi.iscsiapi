import infi.iscsiapi
from infi.vendata.integration_tests import TestCase
from infi.vendata.integration_tests.iscsi import setup_iscsi_network_interface_on_host, setup_iscsi_on_infinibox
from unittest import SkipTest
from infi.os_info import get_platform_string
from subprocess import check_output
from infi.iscsiapi import auth as iscsi_auth
from infi.pyutils.contexts import contextmanager
from time import sleep
from logging import getLogger
from platform import node

INBOUND_USERNAME = "chapuser"
INBOUND_SECRET = "chappass123467"
OUTBOUND_USERNAME = "chap_user2"
OUTBOUND_SECRET = "PASS-chap_8&1231"

INBOUND_USERNAME2 = "chapuser2"
INBOUND_SECRET2 = "chappass1234672"
OUTBOUND_USERNAME2 = "chap_user22"
OUTBOUND_SECRET2 = "PASS-chap_8&12312"

logger = getLogger(__name__)


class ISCSIapiHostTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        def _purge_and_retry(system):
            '''workaround for INFINIBOX-26166'''
            try:
                system.purge()
            except:
                sleep(20)
                system.purge()

        cls.skip_if_not_available()
        cls.system = cls.system_factory.allocate_infinidat_system(labels=(['ci-ready', 'iscsi', 'infinibox-3.0']),
                                                                  purpose_string="iscsiapi Tests",
                                                                  timeout_in_seconds=3600)
        _purge_and_retry(cls.system)
        cls.system_sdk = cls.system.get_infinisdk()
        cls.system_sdk.login()
        cls.iscsiapi = infi.iscsiapi.get_iscsiapi()
        cls.hostname = node().split('.')[0]
        cls.auth1 = iscsi_auth.MutualChapAuth(INBOUND_USERNAME, INBOUND_SECRET, OUTBOUND_USERNAME, OUTBOUND_SECRET)
        cls.auth2 = iscsi_auth.MutualChapAuth(INBOUND_USERNAME2, INBOUND_SECRET2, OUTBOUND_USERNAME2, OUTBOUND_SECRET2)
        if not setup_iscsi_network_interface_on_host():
            sleep(20)
            assert setup_iscsi_network_interface_on_host()

    @contextmanager
    def another_system_context(self):
        system = self.system_factory.allocate_infinidat_system(labels=(['ci-ready', 'iscsi']))
        system.purge()
        system.get_infinisdk().login()
        try:
            yield system
        finally:
            system.purge()
            system.release()

    def setUp(self):
        self.addCleanup(self._cleanup_iscsi_connections)

    def _cleanup_iscsi_connections(self):
        self.iscsiapi.undiscover()

    @classmethod
    def tearDownClass(cls):
        from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        try:
            purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        finally:
            cls.system.purge()
            cls.system.release()

    @classmethod
    def skip_if_not_available(cls):
        try:
            infi.iscsiapi.get_iscsiapi()
        except ImportError:
            raise SkipTest("not available on this platform")

    def _create_host(self, hostname, sdk=None):
        ibox = sdk or self.system_sdk
        host = ibox.hosts.create(name=hostname)
        host.add_port(address=self.iscsiapi.get_source_iqn())
        if sdk is None:
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
        return host.get_security_method(from_cache=False)

    def _solaris_debug_dump(self):
        commands = [
                    "iscsiadm list initiator-node 2>&1 || true",
                    "iscsiadm list discovery 2>&1 || true",
                    "iscsiadm list target-param -v 2>&1 || true",
                    "iscsiadm list discovery-address -v 2>&1 || true",
                    "iscsiadm list target -v 2>&1 || true",
                    ]
        for command in commands:
            logger.debug(command)
            logger.debug(check_output(command, shell=True))

    def _get_infinibox_major_version(self, system):
        return int(system.get_version()[0])

    def _get_system_net_space(self, system):
        '''Temp workaround unit this INFRADEV-7576 is fixed'''
        from infinisdk_internal.exceptions import NetworkConfigError
        try:
            net_space = setup_iscsi_on_infinibox(system)
        except NetworkConfigError:
            sleep(10)
            net_space = setup_iscsi_on_infinibox(system)
        return net_space

    def _assert_number_of_active_sessions(self, target, expected, ibox_version):
        actual = len(self.iscsiapi.get_sessions(target))
        message = 'We expected {0} connections to target {1} but found {2}'.format(expected, target.get_iqn(), actual)
        self.assertEqual(actual, expected, message)

    def _service_stop_check_start_check(self, target, ibox_version):
        from control_iscsi_serivce import get_platform_specific_iscsi_service
        iscsi_service = get_platform_specific_iscsi_service()
        iscsi_service.stop()
        self._assert_number_of_active_sessions(target, 0, ibox_version)
        iscsi_service.start()
        self._assert_number_of_active_sessions(target, len(target.get_endpoints()), ibox_version)

    @contextmanager
    def _iscsi_connection_context(self, net_space, host, auth, ibox_version=3):
        current_auth = self._change_auth_on_ibox(host, auth)
        self.assertEqual(current_auth, auth.get_auth_name())
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        self.iscsiapi.login_all(target, auth)
        self._assert_number_of_active_sessions(target, len(target.get_endpoints()), ibox_version)

        try:
            yield target
        finally:
            self.iscsiapi.logout_all(target)
            self._assert_number_of_active_sessions(target, 0, ibox_version)
            self.iscsiapi.undiscover(target)

    def _assert_discovery_login_logout(self, net_space, host, auth, ibox_version=3):
        with self._iscsi_connection_context(net_space, host, auth, ibox_version) as target:
            pass

    def _assert_discovery_dual_login(self, net_space, host, auth, ibox_version=3):
        with self._iscsi_connection_context(net_space, host, auth, ibox_version) as target:
            self.iscsiapi.login_all(target, auth)

    def _assert_discovery_login_logout_consistent(self, net_space, host, auth, ibox_version):
        with self._iscsi_connection_context(net_space, host, auth, ibox_version) as target:
            self._service_stop_check_start_check(target, ibox_version)

    def _assert_login_to_two_systems(self, net_space, host, auth1, auth2, ibox_version):
        with self.another_system_context() as system:
            sdk = system.get_infinisdk()
            another_ibox_version = self._get_infinibox_major_version(sdk)
            another_net_space = self._get_system_net_space(sdk)
            another_host = self._create_host("another_host", sdk)
            with self._iscsi_connection_context(net_space, host, auth1, ibox_version) as target1:
                with self._iscsi_connection_context(another_net_space, another_host, auth2, another_ibox_version) as target2:
                    pass

    def _assert_login_to_two_systems_consistent(self, net_space, host, auth1, auth2, ibox_version):
        with self.another_system_context() as system:
            sdk = system.get_infinisdk()
            another_ibox_version = self._get_infinibox_major_version(sdk)
            another_net_space = setup_iscsi_on_infinibox(sdk)
            another_host = self._create_host("another_host", sdk)
            with self._iscsi_connection_context(net_space, host, auth1, ibox_version) as target1:
                with self._iscsi_connection_context(another_net_space, another_host, auth2, another_ibox_version) as target2:
                    self._service_stop_check_start_check(target1, ibox_version)
                    self._service_stop_check_start_check(target2, another_ibox_version)

    def test_01_iscsi_software(self):
        iscsi_sw = infi.iscsiapi.get_iscsi_software_initiator()
        if get_platform_string().startswith('solaris'):
            raise SkipTest("iSCSI is installed by default on Solaris")
        if not iscsi_sw.is_installed():
            iscsi_sw.install()
            iscsi_sw.uninstall()
            iscsi_sw.install()
        self.assertNotEqual(iscsi_sw.is_installed, True)

    def test_020_iscsiapi_set_source_iqn(self):
        from infi.dtypes.iqn import IQN, InvalidIQN
        if get_platform_string().startswith('windows'):
            self.iscsiapi.reset_source_iqn()
        new_iqn_string = 'iqn.1991-05.com.microsoft:asdasd'
        invalid_iqn_type_a = '1'
        invalid_iqn_type_b = ''
        original_iqn = self.iscsiapi.get_source_iqn()
        self.iscsiapi.set_source_iqn(new_iqn_string)
        self.assertEqual(type(self.iscsiapi.get_source_iqn()), IQN)
        self.assertEqual(str(self.iscsiapi.get_source_iqn()), new_iqn_string)
        self.assertRaises(InvalidIQN, self.iscsiapi.set_source_iqn, invalid_iqn_type_a)
        self.assertRaises(InvalidIQN, self.iscsiapi.set_source_iqn, invalid_iqn_type_b)
        self.iscsiapi.set_source_iqn(str(original_iqn))
        self.assertEqual(str(self.iscsiapi.get_source_iqn()), original_iqn)

    def test_021_iscsiapi_reset_source_iqn_linux(self):
        if not get_platform_string().startswith('linux'):
            raise SkipTest("linux test skipping other platforms")
        old_iqn = self.iscsiapi.get_source_iqn()
        self.iscsiapi.reset_source_iqn()  # in linux every run generate a different IQN
        self.assertNotEqual(old_iqn, self.iscsiapi.get_source_iqn())

    def test_022_iscsiapi_reset_source_iqn_windows(self):
        from infi.execute import execute_assert_success
        from infi.dtypes.iqn import IQN, InvalidIQN
        if not get_platform_string().startswith('windows'):
            raise SkipTest("windows test skipping other platforms")
        execute_assert_success(['iscsicli', 'NodeName', 'invalid.iqn'])
        self.assertRaises(InvalidIQN, self.iscsiapi.get_source_iqn)
        self.iscsiapi.reset_source_iqn()
        self.assertEqual(IQN, type(self.iscsiapi.get_source_iqn()))

    def test_03_discover_undiscover(self):
        self.iscsiapi.undiscover()
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)
        net_space = self._get_system_net_space(self.system_sdk)
        target = self.iscsiapi.discover(net_space.get_field('ips')[0].ip_address)
        self.addCleanup(self.iscsiapi.logout_all, target)
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 1)
        self.assertEqual(type(target), infi.iscsiapi.base.Target)
        self.assertEqual(target.get_discovery_endpoint().get_ip_address(), net_space.get_field('ips')[0].ip_address)
        self.assertNotEqual(target.get_iqn(), None)
        self.assertEqual(self.iscsiapi.get_discovered_targets()[0].get_iqn(), target.get_iqn())
        self.iscsiapi.undiscover(target)
        self.assertEqual(len(self.iscsiapi.get_discovered_targets()), 0)

    def test_04_login(self):
        net_space = self._get_system_net_space(self.system_sdk)
        ibox_version = self._get_infinibox_major_version(self.system_sdk)
        host = self._create_host(self.hostname)
        auth = iscsi_auth.NoAuth()

        self._assert_discovery_login_logout(net_space, host, auth, ibox_version)
        self._assert_discovery_login_logout(net_space, host, auth, ibox_version)
        self._assert_login_to_two_systems(net_space, host, auth, auth, ibox_version)
        self._assert_discovery_dual_login(net_space, host, auth, ibox_version)

    def test_05_chap_login(self):
        if get_platform_string().startswith('solaris'):
            raise SkipTest("iSCSI CHAP on Solaris not supported - INFINIBOX-25831")

        net_space = self._get_system_net_space(self.system_sdk)
        ibox_version = self._get_infinibox_major_version(self.system_sdk)
        host = self._create_host(self.hostname)
        auth1 = iscsi_auth.ChapAuth(INBOUND_USERNAME, INBOUND_SECRET)
        auth2 = iscsi_auth.ChapAuth(INBOUND_USERNAME2, INBOUND_SECRET2)

        self._assert_discovery_login_logout(net_space, host, auth1, ibox_version)
        self._assert_discovery_login_logout(net_space, host, auth1, ibox_version)

        self._assert_login_to_two_systems(net_space, host, auth1, auth2, ibox_version)
        self._assert_login_to_two_systems(net_space, host, iscsi_auth.NoAuth(), iscsi_auth.NoAuth(), ibox_version)

    def test_06_mutual_chap_login(self):
        if get_platform_string().startswith('solaris'):
            raise SkipTest("iSCSI CHAP on Solaris not supported - INFINIBOX-25831")

        net_space = self._get_system_net_space(self.system_sdk)
        ibox_version = self._get_infinibox_major_version(self.system_sdk)
        host = self._create_host(self.hostname)

        self._assert_discovery_login_logout(net_space, host, self.auth1, ibox_version)
        self._assert_discovery_login_logout(net_space, host, self.auth1, ibox_version)
        if get_platform_string().startswith('windows'):
            self._assert_login_to_two_systems(net_space, host, self.auth1, self.auth1, ibox_version)
        else:
            self._assert_login_to_two_systems(net_space, host, self.auth1, self.auth2, ibox_version)
        self._assert_login_to_two_systems(net_space, host, iscsi_auth.NoAuth(), iscsi_auth.NoAuth(), ibox_version)

    def test_07_consistent_login(self):
        if get_platform_string().startswith('windows'):
            raise SkipTest("not available on this platform")
        net_space = self._get_system_net_space(self.system_sdk)
        host = self._create_host(self.hostname)
        ibox_version = self._get_infinibox_major_version(self.system_sdk)
        no_auth = iscsi_auth.NoAuth()
        chap_auth1 = iscsi_auth.ChapAuth(INBOUND_USERNAME, INBOUND_SECRET)
        chap_auth2 = iscsi_auth.ChapAuth(INBOUND_USERNAME2, INBOUND_SECRET2)
        self._assert_discovery_login_logout_consistent(net_space, host, no_auth, ibox_version)
        self._assert_login_to_two_systems_consistent(net_space, host, no_auth, no_auth, ibox_version)
        if not get_platform_string().startswith('solaris'):  # INFINIBOX-25831
            self._assert_discovery_login_logout_consistent(net_space, host, chap_auth1, ibox_version)
            self._assert_discovery_login_logout_consistent(net_space, host, self.auth1, ibox_version)
            self._assert_login_to_two_systems_consistent(net_space, host, chap_auth1, chap_auth2, ibox_version)
            self._assert_login_to_two_systems_consistent(net_space, host, self.auth1, self.auth2, ibox_version)

import requests
requests.packages.urllib3.disable_warnings()
