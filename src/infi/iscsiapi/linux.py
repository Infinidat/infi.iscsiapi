from infi.execute import execute_assert_success, execute
from . import base
from infi.dtypes.iqn import IQN
import infi.pkgmgr

from logging import getLogger
logger = getLogger(__name__)

ISCSI_CONNECTION_CONFIG = '/var/lib/iscsi/nodes'
ISCSI_INITIATOR_IQN_FILE = '/etc/iscsi/initiatorname.iscsi'

class LinuxISCSIapi(base.ConnectionManager):

    def _pars_iscsiadm_session_output(self, output):
        '''return list of dicts which contain the parsed iscsiadm output
        '''
        import re
        availble_targets = []
        regex = re.compile(r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)\,(?P<no_conn>\d+)\ (?P<iqn>.+)')
        for session in output.splitlines():
            availble_targets.append(regex.search(session).groupdict())
        return availble_targets

    def _pars_connection_config(self):
        import os
        import re
        availble_targets = []
        if not os.path.exists(ISCSI_CONNECTION_CONFIG):
            return availble_targets
        if not os.path.isdir(ISCSI_CONNECTION_CONFIG):
            return availble_targets
        for target in os.listdir(ISCSI_CONNECTION_CONFIG):
            iqn = target
            for end_point in os.listdir(ISCSI_CONNECTION_CONFIG + '/' + target):
                regex = re.compile(r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\,(?P<dst_port>\d+)\,(?P<no_conn>\d+)')
                session = regex.search(end_point).groupdict()
                session['iqn'] = iqn
                availble_targets.append(session)
        return availble_targets

    def _pars_discovery_address(self, iqn):
        '''get an iqn of discovered target and return the discovery ip address
        '''
        import os
        import re
        regex = re.compile('node.discovery_address = 'r'(?P<ip>\d+\.\d+\.\d+\.\d+)')
        _ = IQN(iqn)  # make sure it's valid iqn
        single_connection = os.listdir(os.path.join(ISCSI_CONNECTION_CONFIG, iqn))[0]
        single_path = os.path.join(ISCSI_CONNECTION_CONFIG, iqn, single_connection, 'default')
        with open(single_path, 'r') as fd:
            for line in fd:
                if re.match(regex, line.strip()):
                    return regex.search(line.strip()).groupdict()['ip']

    def _get_initiator_ip_using_sysfs(self, target_ip_address):
        ''' receives destination ip address as a string and return the initiator ip address
        '''
        import os
        from glob import glob
        SYSFS_CONN_BASE_DIR = os.path.join('/sys', 'class', 'scsi_host')
        for host in os.listdir(SYSFS_CONN_BASE_DIR):
            try:
                target_ip_address_file = glob(os.path.join(SYSFS_CONN_BASE_DIR, host, 'device', 'session*',
                                                      'connection*', 'iscsi_connection', 'connection*', 'address'))
            except:
                continue
            if target_ip_address_file == []:
                continue
            target_ip_address_file = target_ip_address_file[0]
            logger.debug("opening file {} to get target ip address".format(target_ip_address_file))
            with open(target_ip_address_file, 'r') as fd:
                if target_ip_address == fd.read().strip():
                    initiator_ip_address_file = glob(os.path.join('/sys', 'class', 'scsi_host', host, 'device', 'iscsi_host',
                                                             host, 'ipaddress'))
                    with open(initiator_ip_address_file[0], 'r') as fd:
                        initiator_ip_address = fd.read().strip()
                        return initiator_ip_address

    def _get_sessions_using_sysfs(self):
        import os
        import re
        from infi.os_info import get_platform_string
        from infi.dtypes.hctl import HCT
        from glob import glob
        sessions = []
        targets = self.get_discovered_targets()
        for host in glob(os.path.join('/sys', 'devices', 'platform', 'host*')):
            if 'centos-5' in get_platform_string() or 'redhat-5' in get_platform_string():
                sessions = glob(os.path.join(host, 'session*', 'connection*', 'iscsi_connection*connection*'))
            else:
                sessions = glob(os.path.join(host, 'session*', 'connection*', 'iscsi_connection', 'connection*'))
            for session_path in sessions:
                try:
                    with open(os.path.join(session_path, 'address'), 'r') as fd:
                        ip_address = fd.read().strip()
                    with open(os.path.join(session_path, 'port'), 'r') as fd:
                        port = fd.read().strip()
                    with open(os.path.join(session_path, 'persistent_address')) as fd:
                        source_ip = fd.read().strip()
                    session_id = os.path.basename(glob(os.path.join(host, 'session*'))[0])
                    if re.match('^session', session_id):
                        uid = re.split('^session', session_id)[1]
                    else:
                        raise RuntimeError("couldn't get session id from {!r}".format(session_path))
                    target_id = os.path.basename(glob(os.path.join(host, 'session*', 'target*'))[0])
                    if re.match('^target', target_id):
                        hct_tuple = re.split('^target', target_id)[1].split(':')
                        hct = HCT(*(int(i) for i in hct_tuple))
                    endpoint = base.Endpoint(ip_address, port)
                    for target in targets:
                        if endpoint in target.get_endpoints():
                            session = base.Session(target, endpoint, source_ip, self.get_source_iqn(), uid, hct)
                            sessions.append(session)
                            break
                except IOError:
                    logger.debug("this path {!r} isn't connected".format(session_path))
                    continue
        return sessions

    def _reload_iscsid_service(self):
        execute_assert_success(['service', 'iscsid', 'restart'])

    def get_discovered_targets(self):
        iqn_list = []
        targets = []
        for connectivity in self._pars_connection_config():
            iqn_list.append(connectivity['iqn'])
        uniq_iqn = list(set(iqn_list))
        for iqn in uniq_iqn:
            endpoints = []
            discovery_endpoint = base.Endpoint(self._pars_discovery_address(iqn), 3260) # TODO parse point
            for connectivity in self._pars_connection_config():
                if connectivity['iqn'] == iqn:
                    endpoints.append(base.Endpoint(connectivity['dst_ip'], connectivity['dst_port']))
            targets.append(base.Target(endpoints, None, None, discovery_endpoint, iqn))
        return targets

    def get_source_iqn(self):
        '''return infi.dtypes.iqn type iqn if iscsi initiator file exists
        '''
        import re
        from os.path import isfile
        if isfile(ISCSI_INITIATOR_IQN_FILE):
            with open(ISCSI_INITIATOR_IQN_FILE, 'r') as fd:
                data = fd.readlines()
                assert len(data) == 1, "something isn't right with {}".format(ISCSI_INITIATOR_IQN_FILE)
                raw_iqn = re.split('InitiatorName=', data[0])
                return IQN(raw_iqn[1].strip())
        else:
            raise

    def set_source_iqn(self, iqn):
        '''receives a string, validates it's an iqn then set it to the host
        NOTE: this restart the iscsi service and may fail active sessions !
        '''
        import shutil
        from os.path import isfile
        _ = IQN(iqn)   # checks iqn is valid
        _ = self.get_source_iqn()  # check file exist and valid
        if not isfile(ISCSI_INITIATOR_IQN_FILE + '.orig'):
            shutil.copy(ISCSI_INITIATOR_IQN_FILE, ISCSI_INITIATOR_IQN_FILE + '.orig')
        replacement_strig = 'InitiatorName=' + iqn
        with open(ISCSI_INITIATOR_IQN_FILE, 'w') as fd:
            fd.write(replacement_strig)
        logger.info("iqn was replaced to {}".format(iqn))
        logger.info("reloading iscsi service")
        self._reload_iscsid_service()

    def discover(self, ip_address, port=3260):
        '''initiate discovery and returns a list of dicts which contain all available targets
        '''
        endpoints = []
        args = ['iscsiadm', '-m', 'discovery', '-t', 'st', '-p', str(ip_address) + ':' + str(port)]
        logger.info("running {}".format(args))
        execute_assert_success(args)
        for target_connectivity in self._pars_connection_config():
            if target_connectivity['dst_ip'] == ip_address:
                iqn = target_connectivity['iqn']
        for target_connectivity in self._pars_connection_config():
            if iqn == target_connectivity['iqn']:
                endpoints.append(base.Endpoint(target_connectivity['dst_ip'], target_connectivity['dst_port']))
        return base.Target(endpoints, None, None, base.Endpoint(ip_address, port), iqn)

    def login(self, target, endpoint, num_of_connections=1):
        args = ['iscsiadm', '-m', 'node', '-l', '-T', target.get_iqn(), '-p',
        endpoint.get_ip_address() + ':' + endpoint.get_port()]
        execute_assert_success(args)
        for session in self._get_sessions_using_sysfs():
            if session.get_target_endpoint() == endpoint:
                return session

    def login_all(self, target):
        args = ['iscsiadm', '-m', 'node', '-l', '-T', str(target.get_iqn())]
        execute_assert_success(args)
        return self.get_sessions(target=target)

    def logout(self, session):
        ip_address = session.get_target_endpoint().get_ip_address()
        execute((['iscsiadm', '-m', 'node', '-u', '-T', str(session.get_target().get_iqn()), '-p', ip_address]))

    def logout_all(self, target):
        execute((['iscsiadm', '-m', 'node', '-u', '-T', str(target.get_iqn())]))

    def get_sessions(self, target=None):
        '''receive a target or None and return a list of all available sessions
        '''
        if target:
            target_sessions = []
            for session in self._get_sessions_using_sysfs():
                if session.get_target_endpoint() in target.get_endpoints():
                    target_sessions.append(session)
            return target_sessions
        else:
            return self._get_sessions_using_sysfs()

    def rescan(self):
        '''rescan all available sessions
        '''
        execute(['iscsiadm', '-m', 'session', '--rescan'])

    def undiscover(self, target=None):
        '''logout from everything and delete all discovered target if target=None otherwise delete only the target
        discovery endpoints
        '''

        if target:
            self.logout_all(target)
            execute(['iscsiadm', '-m', 'node', '-o', 'delete', str(target.get_iqn())])
        else:
            for target in self.get_discovered_targets():
                self.logout_all(target)
            execute(['iscsiadm', '-m', 'node', '-o', 'delete'])

class LinuxSoftwareInitiator(base.SoftwareInitiator):
    def is_installed(self):
        ''' In linux, return True if iSCSI initiator sw is installed otherwise return False
        '''
        from infi.os_info import get_platform_string
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            return pkgmgr.is_package_installed('iscsi-initiator-utils')
        if 'ubuntu' in get_platform_string() or 'suse' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            return pkgmgr.is_package_installed('open-iscsi')

    def install(self):
        from infi.os_info import get_platform_string
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.install_package('iscsi-initiator-utils')
        if 'ubuntu' in get_platform_string() or 'suse' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.install_package('open-iscsi')

    def uninstall(self):
        from infi.os_info import get_platform_string
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.remove_package('iscsi-initiator-utils')
            execute(['yum', 'erase', '-y', 'iscsi-initiator-utils'])
        if 'ubuntu' in get_platform_string() or 'suse' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.remove_package('open-iscsi')
