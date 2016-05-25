from infi.execute import execute_assert_success, execute, ExecutionError
from . import base

from logging import getLogger
logger = getLogger(__name__)

ISCSI_FS_PATH = '/var/lib/iscsi/nodes'

class LinuxISCSIapi(base.ConnectionManager):

    def _pars_linux_iscsiadm_output(self, output):
        '''return list of dicts which contain the parsed iscsiadm output
        '''
        import re
        availble_targets = []
        #regex = re.compile(r'(?P<dst_ip>^\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)\,(?P<no_conn>\d+)\ (?P<iqn>.+)')
        # need to remove starts with ip ^ to support also sessions moved from match to search
        regex = re.compile(r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)\,(?P<no_conn>\d+)\ (?P<iqn>.+)')
        for session in output.splitlines():
            availble_targets.append(regex.search(session).groupdict())
        return availble_targets

    def _pars_sysfs(self):
        import os
        import re
        availble_targets = []
        for target in os.listdir(ISCSI_FS_PATH):
            iqn = target
            for end_point in os.listdir(ISCSI_FS_PATH + '/' + target):
                regex = re.compile(r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\,(?P<dst_port>\d+)\,(?P<no_conn>\d+)')
                session = regex.search(end_point).groupdict()
                session['iqn'] = iqn
                availble_targets.append(session)
        return availble_targets


    def discover(self, ip_address, port=3260):
        '''initiate discovery and returns a list of dicts which contain all available targets
        '''
        endpoints = []
        args = ['iscsiadm', '-m', 'discovery', '-t', 'st', '-p', str(ip_address) + ':' + str(port) ]
        logger.info("running {}".format(args))
        process = execute_assert_success(args)
        for target_connectivity in self._pars_sysfs():
            if target_connectivity['dst_ip'] == ip_address:
                iqn = target_connectivity['iqn']
        for target_connectivity in self._pars_sysfs():
            if iqn == target_connectivity['iqn']:
                endpoint = base.Endpoint(target_connectivity['dst_ip'], target_connectivity['dst_port'])
                endpoints.append(endpoint)
        return base.Target(endpoints, None, None, ip_address, iqn)

#    def discover_target(self, ip_addr):
#        '''initiate discovery and returns a list of dicts which contain all available targets
#        '''
#        process = execute_assert_success(['iscsiadm', '-m', 'discovery', '-t', 'st', '-p', ip_addr])
#        return self._pars_linux_iscsiadm_output(process.get_stdout())

    def login(self, target, endpoint, num_of_connections=1):
        args = ['iscsiadm', '-m', 'node', '-l', '-T', target.get_iqn(), '-p',\
        endpoint.get_ip_address() + ':' + endpoint.get_port()]
        execute_assert_success(args)
#       return session


    def login_to_target(self, target_iqn, ip=None):
        '''receives an iqn as string and login to it with ip tries to connect to the target ip
        '''
        if not ip:
            execute_assert_success(['iscsiadm', '-m', 'node', '-l', '-T', target_iqn])
        else:
            execute_assert_success(['iscsiadm', '-m', 'node', '-l', '-T', target_iqn, '-p', ip])
        #iscsiadm --m node  --targetname "iqn.2009-11.com.infinidat:storage:infinibox-sn-30189"  -p 172.16.40.153:3260 --op=update --name node.session.auth.authmethod --value=CHAP
        #-op=update --name node.session.auth.username --value=
        #-op=update --name node.session.auth.password --value=

    def login_to_all_availble_targets(self):
        execute_assert_success(['iscsiadm', '-m', 'node', '-l'])

    def logout_from_target(self, iqn):
        '''receives an iqn as string and logs out of it
        '''
        execute((['iscsiadm', '-m', 'node', '-u', '-T', iqn]))

    def logout_from_all_targets(self):
        execute((['iscsiadm', '-m', 'node', '-u']))

    def get_sessions(self, target=None):
        try:
            if target:
                process = execute_assert_success(['iscsiadm', '-m', 'session', '-n', target.get_iqn()])
            else:
                process = execute_assert_success(['iscsiadm', '-m', 'session'])
        except ExecutionError as e:
                logger.error(e)
                return []
        return
    def get_sessions(self, target=None):
        '''returns a list of dicts which contain all active sessions or only iqn specific active session
        '''
        # import os
        # if not os.path.isdir(ISCSI_FS_PATH):
            # logger.error("storage isn't discoverable from this host when it should be")
            # return
        # return os.listdir(ISCSI_FS_PATH)
        try:
            if target:
                process = execute_assert_success(['iscsiadm', '-m', 'session', '-n', target.get_iqn()])
            else:
                process = execute_assert_success(['iscsiadm', '-m', 'session'])
        except ExecutionError as e:
                logger.error(e)
                return []
        if target:

        self._pars_linux_iscsiadm_output(process.get_stdout())

    def rescan(self):
        '''rescan all available sessions
        '''
        execute(['iscsiadm', '-m', 'session', '--rescan'])

    def rescan_all_sessions(self):
        '''rescan all available sessions
        '''
        execute(['iscsiadm', '-m', 'session', '--rescan'])

    def delete_discovered_sessions(self, iqn=None, ip=None):
        '''with no arguments delete all discover sessions
        with ip or iqn delete a specific ip session or all sessions to a specific iqn
        '''
        if not iqn and not ip:
            execute(['iscsiadm', '-m', 'node', '-o', 'delete'])
        elif iqn and not ip:
            execute(['iscsiadm', '-m', 'node', '-o', 'delete', iqn])
        elif ip and not iqn:
            execute(['iscsiadm', '-m', 'node', '-o', 'delete', '-p', ip])
        else:
            raise AttributeError("function can't receive both ip and iqn.")

class LinuxSoftwareInitiator(base.SoftwareInitiator):
    def is_installed(self):
        ''' In linux, return True if iSCSI initiator sw is installed otherwise return False
        '''
        from infi.os_info import get_platform_string
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            logger.debug("checking if iSCSI sw is installed")
            process = execute(['rpm', '-q', '--quiet', 'iscsi-initiator-utils'])
        if process.get_returncode() != 0:
            logger.debug("iscsi sw isn't installed")
            return False
        else:
            logger.debug("iscsi sw installed")
            return True

    def install(self):
        from infi.os_info import get_platform_string
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            execute_assert_success(['yum', 'install', '-y', 'iscsi-initiator-utils'])

    def uninstall(self):
        from infi.os_info import get_platform_string
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            execute(['yum', 'erase', '-y', 'iscsi-initiator-utils'])
