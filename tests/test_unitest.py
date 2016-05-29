from infi.vendata.integration_tests import TestCase
from mock import patch, MagicMock, mock_open
from infi.execute import execute_assert_success
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#from psutil._common import snic, snicstats
import infi.iscsiapi.windows
#reduce urlib error
import requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


rh_discovery = '''
172.16.40.153:3260,1 iqn.2009-11.com.infinidat:storage:infinibox-sn-30189
172.16.40.154:3260,1 iqn.2009-11.com.infinidat:storage:infinibox-sn-30189
172.16.40.155:3260,1 iqn.2009-11.com.infinidat:storage:infinibox-sn-30189
172.16.40.156:3260,1 iqn.2009-11.com.infinidat:storage:infinibox-sn-30189
172.16.40.157:3260,1 iqn.2009-11.com.infinidat:storage:infinibox-sn-30189
172.16.40.158:3260,1 iqn.2009-11.com.infinidat:storage:infinibox-sn-30189
'''

# if_net_result = {
    # 'eth0': [snic(family=2, address='172.16.84.64', netmask='255.255.224.0', broadcast='172.16.95.255', ptp=None),
             # snic(family=2, address='172.16.87.12', netmask='255.255.224.0', broadcast='172.16.95.255', ptp=None),
             # snic(family=10, address='fe80::250:56ff:fe99:dd7c%eth0', netmask='ffff:ffff:ffff:ffff::', broadcast=None, ptp=None),
             # snic(family=17, address='00:50:56:99:dd:7c', netmask=None, broadcast='ff:ff:ff:ff:ff:ff', ptp=None)],
    # 'eth1': [snic(family=2, address='172.16.59.28', netmask='255.255.224.0', broadcast='172.16.63.255', ptp=None),
             # snic(family=10, address='fe80::250:56ff:fe99:7e13%eth1', netmask='ffff:ffff:ffff:ffff::', broadcast=None, ptp=None),
             # snic(family=17, address='00:50:56:99:7e:13', netmask=None, broadcast='ff:ff:ff:ff:ff:ff', ptp=None)],
    # 'lo': [snic(family=2, address='127.0.0.1', netmask='255.0.0.0', broadcast=None, ptp=None),
           # snic(family=10, address='::1', netmask='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', broadcast=None, ptp=None),
           # snic(family=17, address='00:00:00:00:00:00', netmask=None, broadcast=None, ptp=None)]}
#
# if_stats_result = {
    # 'eth0': snicstats(isup=True, duplex=2, speed=10000, mtu=9000),
    # 'eth1': snicstats(isup=False, duplex=2, speed=10000, mtu=1500),
    # 'lo': snicstats(isup=True, duplex=0, speed=0, mtu=16436)}
#
#
# class ISCSIapiInfiniboxTestCase(TestCase):
    # @classmethod
    # def setUpClass(cls):
        # cls.system = cls.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        # cls.system.purge()
#
    # @classmethod
    # def tearDownClass(cls):
        # from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        # try:
            # purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        # except:
            # pass
        # cls.system.purge()
        # cls.system.release()

     #def test_iscsi_sw(cls):
        # if is_iscsi_sw_installed():
            # _uninstall_iscsi_software_initiator()
            # install_iscsi_software_initiator()
        # else:
            # install_iscsi_software_initiator()
        # self.assertNotEqual(is_iscsi_sw_installed, True)
#

#class AllocationTestCase(TestCase):
#    def test_iscsi_system_allocation(self):
#        system = self.system_factory.allocate_infinidat_system(labels=(['iscsi']))
#        system.release()


class ISCSIapi_host_TestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.system = cls.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        cls.system.purge()
        cls.system_sdk = cls.system.get_infinisdk()

    @classmethod
    def tearDownClass(cls):
        from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        try:
            purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        except:
            pass
        cls.system.purge()
        cls.system.release()

    # def test_iscsi_sw_linux(self):
        # from unittest import SkipTest
        # from infi.os_info import get_platform_string
        # if not 'redhat' in get_platform_string() and not 'centos' in get_platform_string():
            # raise SkipTest("This test can only be run only on linux")
        # import infi.iscsiapi.linux
        # linux_iscsi = infi.iscsiapi.linux.LinuxISCSIapi()
        # if linux_iscsi.is_installed():
            # linux_iscsi.uninstall()
            # linux_iscsi.install()
        # else:
            # linux_iscsi.install()
        # self.assertNotEqual(linux_iscsi.is_installed, True)

    def test_01_iscsi_sw_win(self):
        from unittest import SkipTest
        from infi.os_info import get_platform_string
        if not 'windows' in get_platform_string():
            raise SkipTest("This test can only be run on windows")
        win_iscsi = infi.iscsiapi.windows.MicrosoftSoftwareInitiator()
        if win_iscsi.is_installed():
            win_iscsi.uninstall()
            win_iscsi.install()
        else:
            win_iscsi.install()
        self.assertEqual(win_iscsi.is_installed(), True)

    def test_iscsiapi_win_set_source_iqn(self):
        from unittest import SkipTest
        from infi.os_info import get_platform_string
        import infi.dtypes.iqn
        if not 'windows' in get_platform_string():
            raise SkipTest("This test can only be run on windows")
        new_iqn_string = 'iqn.1991-05.com.microsoft:asdasd'
        win_iscsi = infi.iscsiapi.windows.WindowsISCSIapi()
        original_iqn = win_iscsi.get_source_iqn()
        win_iscsi.set_source_iqn(new_iqn_string)
        self.assertEqual(type(win_iscsi.get_source_iqn()), infi.dtypes.iqn.IQN)
        self.assertEqual(str(win_iscsi.get_source_iqn()), new_iqn_string)
        win_iscsi.set_source_iqn(str(original_iqn))
        self.assertEqual(str(win_iscsi.get_source_iqn()), original_iqn)

    def test_discover_undiscover(self):
        from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        win_iscsi = infi.iscsiapi.windows.WindowsISCSIapi()
        win_iscsi.undiscover()
        self.assertEqual(len(win_iscsi.get_discovered_targets()), 0 )
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = win_iscsi.discover(net_space.get_field('ips')[0].ip_address)
        self.assertEqual(len(win_iscsi.get_discovered_targets()), 1 )
        self.assertEqual(type(target), infi.iscsiapi.base.Target )
        self.assertEqual(target.get_discovery_endpoint(),net_space.get_field('ips')[0].ip_address)
        self.assertNotEqual(target.get_iqn(), None )
        self.assertEqual(win_iscsi.get_discovered_targets()[0].get_iqn(), target.get_iqn())
        win_iscsi.undiscover(target)
        self.assertEqual(len(win_iscsi.get_discovered_targets()), 0 )

    def test_login_logout_win(self):
        from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        win_iscsi = infi.iscsiapi.windows.WindowsISCSIapi()
        win_iscsi.undiscover()
        if win_iscsi.get_discovered_targets() != []:
            for target in win_iscsi.get_discovered_targets():
                win_iscsi.logout(target)
        self.assertEqual(len(win_iscsi.get_discovered_targets()), 0 )
        net_space = setup_iscsi_on_infinibox(self.system_sdk)
        target = win_iscsi.discover(net_space.get_field('ips')[0].ip_address)
        sessions = win_iscsi.login_all(target)
        self.assertEqual(len(sessions), len(target.get_endpoints()))
        win_iscsi.logout_all(target)
        sessions = win_iscsi.get_sessions()
        self.assertEqual(len(sessions), 0)

    # def test_login_logout_linux(self):
        # from unittest import SkipTest
        # from infi.os_info import get_platform_string
        # from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        # import infi.iscsiapi.linux
        # if not 'redhat' in get_platform_string() and not 'centos' in get_platform_string():
            # raise SkipTest("This test can only be run only on linux")
        # system = self.system.get_infinisdk()
        # net_space = setup_iscsi_on_infinibox(system)
        # linux_iscsi = infi.iscsiapi.linux.LinuxISCSIapi()
        # linux_iscsi.logout_from_all_targets()
        # linux_iscsi.discover_target(net_space.get_field('ips')[0].ip_address)
        # target_iqn = net_space.get_field('properties')['iscsi_iqn']
        # for field in net_space.get_field('ips'):
            # linux_iscsi.login_to_target(target_iqn, ip=field.ip_address)
            # self.assertEquals(linux_iscsi.get_sessions()['dst_ip'], field.ip_address)
            # linux_iscsi.logout_from_target(target_iqn)
            # self.assertEquals(linux_iscsi.get_sessions(), [])




    # def test_disover_target(self):
    #     import infi.iscsiapi.linux
    #     linux_iscsi = infi.iscsiapi.linux.LinuxISCSIapi()
    #     with patch.object(linux_iscsi.discover_target, process) as patch_exe:
    #         patch_exe.return_value = rh_discovery
    #         result = linux_iscsi.discover_target('10.0.0.1')
    #         self.assertEquals(result[2].get('ip'), '172.16.40.155')

# class IscsiProvisioningTestCase(TestCase):
    # @classmethod
    # def setUpClass(cls):
        # cls.system = cls.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        # cls.system.purge()
#
    # @classmethod
    # def tearDownClass(cls):
        # from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        # try:
            # purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        # except:
            # pass
        # cls.system.purge()
        # cls.system.release()
#
    # def test__get_host_iscsi_iqn(self):
        # prov = provisioning.SystemProvisioning(self.system.get_infinisdk())
        # one_line_iqn='InitiatorName=iqn.1994-05.com.redhat:648167ad5a2a\n'
        # two_lines_iqn='InitiatorName=iqn.1994-05.com.redhat:648167ad5a2a\nInitiatorName=iqn.1994-05.com.redhat:aaaa2222\n'
        # with patch('infi.vendata.integration_tests.provisioning.open', mock_open(read_data=one_line_iqn), create=True):
            # self.assertEquals('iqn.1994-05.com.redhat:648167ad5a2a', prov._get_host_iscsi_iqn())
        # with patch('infi.vendata.integration_tests.provisioning.open', mock_open(read_data=two_lines_iqn), create=True):
            # self.assertRaises(AttributeError, prov._get_host_iscsi_iqn)


# class IscsiConnectivityTestCase(TestCase):
    # @classmethod
    # def setUpClass(cls):
        # super(IscsiConnectivityTestCase, cls).setUpClass()
        # from unittest import SkipTest
        # from infi.os_info import get_platform_string
        # if not 'redhat' in get_platform_string() and not 'centos' in get_platform_string():
            # raise SkipTest("iSCSI currently only supported on Centos and RH")
        # cls.system = cls.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        # cls.system.purge()
#
    # @classmethod
    # def tearDownClass(cls):
        # from infi.vendata.integration_tests.iscsi import purge_iscsi_on_infinibox
        # try:
            # purge_iscsi_on_infinibox(cls.system.get_infinisdk())
        # except:
            # pass
        # cls.system.purge()
        # cls.system.release()
        # super(IscsiConnectivityTestCase, cls).tearDownClass()
#
    # def test_setup_iscsi_on_infinibox(self):
        # from infi.vendata.integration_tests.iscsi import setup_iscsi_on_infinibox
        # system = self.system.get_infinisdk()
        # net_space = setup_iscsi_on_infinibox(system)
        # self.assertEquals(len(system.network_spaces.get_all().to_list()), 1)
        # self.assertEquals(system.network_spaces.get().get_name(), net_space.get_name())
#
    # def test_is_iscsi_nic_availalbe(self):
        # from infi.vendata.integration_tests import iscsi
        # import psutil
        # with patch.object(psutil, 'net_if_addrs') as net_if_addrs:
            # net_if_addrs.return_value = if_net_result
            # with patch.object(psutil, 'net_if_stats') as net_if_stats:
                # net_if_stats.return_value = if_stats_result
                # self.assertEquals(iscsi.is_iscsi_nic_availalbe(), None)
#
    # def test_provisioning__iscsi(self):
        # from infi.vendata.integration_tests import iscsi
        # iscsi.setup_iscsi_software_initiator()
        # iscsi.setup_iscsi_network_interface_on_host()
        # network_space = iscsi.setup_iscsi_on_infinibox(self.system.get_infinisdk())
        # prov = provisioning.SystemProvisioning(self.system)
        # prov.iscsi_connect_host_to_system(self.system.get_infinisdk())
        # self.addCleanup(prov.iscsi_disconnect_host_from_system, self.system.get_infinisdk())
        # prov.iscsi_connect_host_to_system(self.system.get_infinisdk())
        # obj, host, volume, device = self.provisioning.provision_volume(self.system, use_iscsi=True)
        # self.provisioning.provision_another_volume(self.system, host)
#
#
# class AllocationTestCase(TestCase):
    # def test_iscsi_system_allocation(self):
        # system = self.system_factory.allocate_infinidat_system(labels=(['iscsi']))
        # system.release()
