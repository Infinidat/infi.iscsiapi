from . import base
from . import auth as iscsiapi_auth
from infi.dtypes.iqn import IQN
from infi.os_info import get_platform_string
import infi.pkgmgr

from logging import getLogger
logger = getLogger(__name__)

if 'ubuntu' in get_platform_string() or 'suse' in get_platform_string():
    ISCSI_CONNECTION_CONFIG = '/etc/iscsi/nodes'
else:
    ISCSI_CONNECTION_CONFIG = '/var/lib/iscsi/nodes'
ISCSI_INITIATOR_IQN_FILE = '/etc/iscsi/initiatorname.iscsi'
GENERATE_COMMAND = 'iscsi-iname'

class LinuxISCSIapi(base.ConnectionManager):

    def _execute(self, cmd):
        from infi.execute import execute
        logger.debug("Running: {}".format(cmd))
        return execute(cmd)

    def _execute_assert_success(self, cmd):
        from infi.execute import execute_assert_success
        logger.debug("Running: {}".format(cmd))
        return execute_assert_success(cmd)

    def _parse_iscsiadm_session_output(self, output):
        '''return list of dicts which contain the parsed iscsiadm output
        '''
        import re
        availble_targets = []
        regex = re.compile(r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)\,(?P<no_conn>\d+)\ (?P<iqn>.+)')
        for session in output.splitlines():
            availble_targets.append(regex.search(session).groupdict())
        return availble_targets

    def _parse_connection_config(self):
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

    def _parse_discovery_address(self, iqn):
        '''get an iqn of discovered target and return the discovery ip address
        '''
        import os
        import re
        import glob
        regex = re.compile('node.discovery_address = 'r'(?P<ip>\d+\.\d+\.\d+\.\d+)')
        _ = IQN(iqn)  # make sure it's valid iqn
        for filepath in glob.glob(os.path.join(ISCSI_CONNECTION_CONFIG, iqn, '*', # target address
                                               'default')):
            try:
                with open(filepath, 'r') as fd:
                    for line in fd:
                        if re.match(regex, line.strip()):
                            return regex.search(line.strip()).groupdict()['ip']
            except (OSError, IOError):
                continue

    def _iter_sessions_in_sysfs(self):
        import os
        import re
        from infi.os_info import get_platform_string
        from infi.dtypes.hctl import HCT
        from glob import glob

        for host in glob(os.path.join('/sys', 'devices', 'platform', 'host*')):
            for session in glob(os.path.join(host, 'session*')):  # usually, one session per host
                uid = re.split('^session', os.path.basename(session))[1]

                if 'centos-5' in get_platform_string() or 'redhat-5' in get_platform_string():
                    connections = glob(os.path.join(session, 'connection*', 'iscsi_connection*connection*'))
                else:
                    connections = glob(os.path.join(session, 'connection*', 'iscsi_connection', 'connection*'))

                for connection in connections:
                    try:
                        with open(os.path.join(connection, 'address'), 'r') as fd:
                            ip_address = fd.read().strip()
                        with open(os.path.join(connection, 'port'), 'r') as fd:
                            port = fd.read().strip()
                        with open(os.path.join(connection, 'persistent_address'), 'r') as fd:
                            source_ip = fd.read().strip()
                        break
                    except (IOError, OSError):
                        logger.debug("connection parameters are missing for {}".format(connection))
                        continue
                else:  # no connections in session
                    logger.debug("no valid connection for session {}".format(session))

                    continue

                for target in glob(os.path.join(session, 'target*')):  # usually, one target per session
                    target_id = os.path.basename(target)
                    endpoint = base.Endpoint(ip_address, port)
                    hct_tuple = re.split('^target', target_id)[1].split(':')
                    hct = HCT(*(int(i) for i in hct_tuple))
                    break
                else:  # no targets in session
                    logger.debug("no targets for session {}".format(session))
                    continue

                yield uid, ip_address, port, source_ip, endpoint, hct

    def _get_sessions_using_sysfs(self):
        sessions = []
        discovered_targets = self.get_discovered_targets()
        source_iqn = self.get_source_iqn()

        for uid, ip_address, port, source_ip, endpoint, hct in self._iter_sessions_in_sysfs():
            for target in discovered_targets:
                if endpoint in target.get_endpoints():
                    session = base.Session(target, endpoint, source_ip, source_iqn, uid, hct)
                    sessions.append(session)
                    break
                else:  # no targets to match for
                    continue
        return sessions

    def _reload_iscsid_service(self):
        import os.path
        if os.path.isfile('/bin/systemctl'):
            self._execute_assert_success(['systemctl', 'restart', 'iscsid'])
        elif os.path.isfile('/etc/init.d/iscsid'):
            self._execute_assert_success(['service', 'iscsid', 'restart'])
        elif os.path.isfile('/etc/init.d/open-iscsi'):
            self._execute_assert_success(['service', 'open-iscsi', 'restart'])
        else:
            logger.error("couldn't find /bin/systemctl or /usr/sbin/service, failed reloading")

    def _remove_comments(self, list_of_strings):
        '''get list of strings and return list of strings without the commented out ones'''
        import re
        no_comment = []
        regex = re.compile(r'^#.+')
        for line in list_of_strings:
            if not re.match(regex, line):
                no_comment.append(line)
        return no_comment

    def _update_node_parameter(self, name, value, target):
        from infi.execute import execute_assert_success
        args = ['iscsiadm', '-m', 'node', '-o', 'update', '-n', name, '-v', value, '-T', target]
        if "password" not in name:
            logger.debug("running {}".format(args))
        else:
            logger.debug("running {}".format(args).replace(value, '***' if value else ''))
        return _execute_assert_success(args)  # we don't want to log the password

    def _set_auth(self, auth, target):
        target_iqn = target.get_iqn()
        if isinstance(auth, iscsiapi_auth.ChapAuth):
            self._update_node_parameter('node.session.auth.authmethod', 'CHAP', target_iqn)
            self._update_node_parameter('node.session.auth.username', auth.get_inbound_username(), target_iqn)
            self._update_node_parameter('node.session.auth.password', auth.get_inbound_secret(), target_iqn)
            self._update_node_parameter('node.session.auth.username_in', '', target_iqn)
            self._update_node_parameter('node.session.auth.password_in', '', target_iqn)
        elif isinstance(auth, iscsiapi_auth.MutualChapAuth):
            self._update_node_parameter('node.session.auth.authmethod', 'CHAP', target_iqn)
            self._update_node_parameter('node.session.auth.username', auth.get_inbound_username(), target_iqn)
            self._update_node_parameter('node.session.auth.password', auth.get_inbound_secret(), target_iqn)
            self._update_node_parameter('node.session.auth.username_in', auth.get_outbound_username(), target_iqn)
            self._update_node_parameter('node.session.auth.password_in', auth.get_outbound_secret(), target_iqn)
        elif isinstance(auth, iscsiapi_auth.NoAuth):
            self._update_node_parameter('node.session.auth.authmethod', 'None', target_iqn)
            self._update_node_parameter('node.session.auth.username', "", target_iqn)
            self._update_node_parameter('node.session.auth.password', "", target_iqn)
            self._update_node_parameter('node.session.auth.username_in', "", target_iqn)
            self._update_node_parameter('node.session.auth.password_in', "", target_iqn)

    def _get_old_iqn(self):
        from os.path import isfile
        if not isfile(ISCSI_INITIATOR_IQN_FILE):
            return
        with open(ISCSI_INITIATOR_IQN_FILE, 'r') as fd:
            return fd.readlines()

    def get_discovered_targets(self):
        iqn_list = []
        targets = []
        for connectivity in self._parse_connection_config():
            iqn_list.append(connectivity['iqn'])
        uniq_iqn = list(set(iqn_list))
        for iqn in uniq_iqn:
            endpoints = []
            discovery_address = self._parse_discovery_address(iqn)
            if discovery_address is None:  # possible race
                continue
            discovery_endpoint = base.Endpoint(discovery_address, 3260)  # TODO parse port
            for connectivity in self._parse_connection_config():
                if connectivity['iqn'] == iqn:
                    endpoints.append(base.Endpoint(connectivity['dst_ip'], connectivity['dst_port']))
            targets.append(base.Target(endpoints, discovery_endpoint, iqn))
        return targets

    def get_source_iqn(self):
        '''return infi.dtypes.iqn type iqn if iscsi initiator file exists
        '''
        from .iscsi_exceptions import NotReadyException
        import re
        from os.path import isfile
        if not isfile(ISCSI_INITIATOR_IQN_FILE):
            raise NotReadyException("iSCSI initiator IQN file not found")
        with open(ISCSI_INITIATOR_IQN_FILE, 'r') as fd:
            data = self._remove_comments(fd.readlines())
            assert len(data) == 1, "something isn't right with {}".format(ISCSI_INITIATOR_IQN_FILE)
            raw_iqn = re.split('InitiatorName=', data[0])
            return IQN(raw_iqn[1].strip())

    def reset_source_iqn(self):
        '''use in case iqn is invalid and regeneration of it is required'''
        process =  self._execute_assert_success([GENERATE_COMMAND])
        iqn = process.get_stdout().strip()
        _ = IQN(iqn) #  validating new IQN
        logger.info("Regeneration of iqn was initiated, old file {}".format(ISCSI_INITIATOR_IQN_FILE) +
                    "had this data in it {!r}, new iqn is:{}".format(self._get_old_iqn(), iqn))
        self.set_source_iqn(iqn)

    def set_source_iqn(self, iqn):
        '''receives a string, validates it's an iqn then set it to the host
        NOTE: this restart the iscsi service and may fail active sessions !
        '''
        import shutil
        from os.path import isfile
        _ = IQN(iqn)   # checks iqn is valid
        logger.info("Old IQN was:{}".format(self._get_old_iqn()))
        replacement_strig = 'InitiatorName=' + iqn
        with open(ISCSI_INITIATOR_IQN_FILE, 'w') as fd:
            fd.write(replacement_strig + "\n")
        logger.info("iqn was replaced to {}".format(iqn))
        self._reload_iscsid_service()

    def discover(self, ip_address, port=3260):
        '''initiate discovery and returns a list of dicts which contain all available targets
        '''
        endpoints = []
        args = ['iscsiadm', '-m', 'discovery', '-t', 'st', '-p', str(ip_address) + ':' + str(port)]
        logger.info("running {}".format(args))
        self._execute_assert_success(args)
        for target_connectivity in self._parse_connection_config():
            if target_connectivity['dst_ip'] == ip_address:
                iqn = target_connectivity['iqn']
        for target_connectivity in self._parse_connection_config():
            if iqn == target_connectivity['iqn']:
                endpoints.append(base.Endpoint(target_connectivity['dst_ip'], target_connectivity['dst_port']))
        return base.Target(endpoints, base.Endpoint(ip_address, port), iqn)

    def login(self, target, endpoint, auth=None, num_of_connections=1):
        if auth is None:
            auth = iscsiapi_auth.NoAuth()
        self._set_auth(auth, target)
        args = ['iscsiadm', '-m', 'node', '-l', '-T', target.get_iqn(), '-p',
        endpoint.get_ip_address() + ':' + endpoint.get_port()]
        self._execute_assert_success(args)
        for session in self._get_sessions_using_sysfs():
            if session.get_target_endpoint() == endpoint:
                return session

    def login_all(self, target, auth=None):
        if auth is None:
            auth = iscsiapi_auth.NoAuth()
        self._set_auth(auth, target)
        args = ['iscsiadm', '-m', 'node', '-l', '-T', str(target.get_iqn())]
        self._execute_assert_success(args)
        return self.get_sessions(target=target)

    def logout(self, session):
        ip_address = session.get_target_endpoint().get_ip_address()
        self._execute((['iscsiadm', '-m', 'node', '-u', '-T', str(session.get_target().get_iqn()), '-p', ip_address]))

    def logout_all(self, target):
        self._execute((['iscsiadm', '-m', 'node', '-u', '-T', str(target.get_iqn())]))

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
        self._execute(['iscsiadm', '-m', 'session', '--rescan'])

    def undiscover(self, target=None):
        '''logout from everything and delete all discovered target if target=None otherwise delete only the target
        discovery endpoints
        '''
        if target:
            self.logout_all(target)
            self._execute(['iscsiadm', '-m', 'node', '-o', 'delete', str(target.get_iqn())])
        else:
            for target in self.get_discovered_targets():
                self.logout_all(target)
            self._execute(['iscsiadm', '-m', 'node', '-o', 'delete'])


class LinuxSoftwareInitiator(base.SoftwareInitiator):
    def is_installed(self):
        ''' In linux, return True if iSCSI initiator sw is installed otherwise return False
        '''
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            return pkgmgr.is_package_installed('iscsi-initiator-utils')
        if 'ubuntu' in get_platform_string() or 'suse' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            return pkgmgr.is_package_installed('open-iscsi')

    def install(self):
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.install_package('iscsi-initiator-utils')
        if 'ubuntu' in get_platform_string() or 'suse' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.install_package('open-iscsi')
            if 'suse-12' in get_platform_string():
                self._execute(['service', 'iscsid', 'start'])

    def uninstall(self):
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.remove_package('iscsi-initiator-utils')
        if 'ubuntu' in get_platform_string() or 'suse' in get_platform_string():
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.remove_package('open-iscsi')
