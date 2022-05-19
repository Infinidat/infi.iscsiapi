from . import base
from . import auth as iscsiapi_auth
from infi.dtypes.iqn import IQN
from infi.os_info import get_platform_string
import infi.pkgmgr
import os

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

    def _parse_discovery_endpoint(self, iqn):
        '''get an iqn of discovered target and return the discovery ip address
        '''
        import re
        IQN(iqn)  # make sure it's a valid iqn
        for end_point in os.listdir(os.path.join(ISCSI_CONNECTION_CONFIG, iqn)):
            filepath = os.path.join(ISCSI_CONNECTION_CONFIG, iqn, end_point)
            # HPT-2193 filepath could be a file with the node info, or a dir that contains a file "default" which
            # has the information
            if os.path.isdir(filepath):
                filepath = os.path.join(filepath, 'default')
            if not os.path.isfile(filepath):
                continue
            try:
                with open(filepath, 'r') as fd:
                    content = fd.read()
            except (OSError, IOError):
                continue
            ip = re.search("node.discovery_address\s*=\s*(\d+\.\d+\.\d+\.\d+)", content)
            port = re.search("node.discovery_port\s*=\s*(\d+)", content)
            if ip is not None and port is not None:
                return base.Endpoint(ip.group(1), int(port.group(1)))

    def get_discovered_targets(self):
        targets = []
        if not os.path.isdir(ISCSI_CONNECTION_CONFIG):
            return targets
        for iqn in os.listdir(ISCSI_CONNECTION_CONFIG):
            endpoints = []
            for end_point in os.listdir(os.path.join(ISCSI_CONNECTION_CONFIG, iqn)):
                dst_ip, dst_port = end_point.split(",")[:2]
                endpoints.append(base.Endpoint(dst_ip, int(dst_port)))
            discovery_endpoint = self._parse_discovery_endpoint(iqn)
            # HPT-2193 discovery_endpoint could be None, we must not fail because of this
            targets.append(base.Target(endpoints, discovery_endpoint, iqn))
        return targets

    def _iter_sessions_in_sysfs(self):
        import re
        from infi.dtypes.hctl import HCT
        from glob import glob

        def sysfs_file_content(path):
            with open(path, 'r') as fd:
                return fd.read().rstrip(' \t\r\n\0')

        for host in glob(os.path.join('/sys', 'devices', 'platform', 'host*')):

            # some older versions of RHEL-based operating systems use the former path variant, others use the latter
            iscsi_host = glob(os.path.join(host, 'iscsi_host*host*')) + \
                         glob(os.path.join(host, 'iscsi_host', 'host*'))

            if not iscsi_host:
                # might be that we didn't find such dirs, no iSCSI here:
                continue

            try:
                source_ip = sysfs_file_content(os.path.join(iscsi_host[0], 'ipaddress'))
            except (IOError, OSError):
                logger.debug("Couldn't access initiator data for {}".format(iscsi_host[0]))
                continue

            for session in glob(os.path.join(host, 'session*')):  # usually, one session per host
                uid = re.split('^session', os.path.basename(session))[1]

                iscsi_session = glob(os.path.join(session, 'iscsi_session*session*')) + \
                                glob(os.path.join(session, 'iscsi_session', 'session*'))
                source_iqn = sysfs_file_content(os.path.join(iscsi_session[0], 'initiatorname'))
                target_iqn = sysfs_file_content(os.path.join(iscsi_session[0], 'targetname'))

                connections = glob(os.path.join(session, 'connection*', 'iscsi_connection*connection*')) + \
                              glob(os.path.join(session, 'connection*', 'iscsi_connection', 'connection*'))

                for connection in connections:
                    try:
                        ip_address = sysfs_file_content(os.path.join(connection, 'address'))
                        port = sysfs_file_content(os.path.join(connection, 'port'))
                        break
                    except (IOError, OSError):
                        logger.debug("connection parameters are missing for {}".format(connection))
                        continue
                else:  # no connections in session
                    logger.debug("no valid connection for session {}".format(session))
                    continue

                target_endpoint = base.Endpoint(ip_address, int(port))

                for target in glob(os.path.join(session, 'target*')):  # usually, one target per session
                    target_id = os.path.basename(target)
                    hct_tuple = re.split('^target', target_id)[1].split(':')
                    hct = HCT(*(int(i) for i in hct_tuple))
                    break
                else:  # no targets in session
                    logger.debug("no targets for session {}".format(session))
                    continue

                yield target_iqn, target_endpoint, source_ip, source_iqn, uid, hct

    def _get_sessions_from_sysfs(self):
        sessions = []
        iqn_to_target = {target.get_iqn(): target for target in self.get_discovered_targets()}

        for target_iqn, target_endpoint, source_ip, source_iqn, uid, hct in self._iter_sessions_in_sysfs():
            if target_iqn not in iqn_to_target:
                # no matching targets
                # TODO should we raise an exception here? Or pass target=None to base.Session?
                # We saw in HPT-2193 that skipping sessions may be a big problem because it means we may miss iSCSI
                # devices and later treat them as local devices instead
                msg = "no valid target for session in sysfs. target endpoint={}:{} target iqn={}"
                logger.debug(msg.format(target_endpoint.get_ip_address(), target_endpoint.get_port(), target_iqn))
                continue
            target = iqn_to_target[target_iqn]
            session = base.Session(target, target_endpoint, source_ip, source_iqn, uid, hct)
            sessions.append(session)
        return sessions

    def _reload_iscsid_service(self):
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
        return execute_assert_success(args)  # we don't want to log the password

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

    def _session_already_active(self, target, target_endpoint):
        for session in self.get_sessions(target=target):
            if target_endpoint == session.get_target_endpoint():
                return session

    def get_source_iqn(self):
        '''return infi.dtypes.iqn type iqn if iscsi initiator file exists
        '''
        from .iscsi_exceptions import NotReadyException
        import re
        from os.path import isfile
        try:
            with open(ISCSI_INITIATOR_IQN_FILE, 'r') as fd:
                data = self._remove_comments(fd.readlines())
                assert len(data) == 1, "something isn't right with {}".format(ISCSI_INITIATOR_IQN_FILE)
                raw_iqn = re.split('InitiatorName=', data[0])
                return IQN(raw_iqn[1].strip())
        except Exception as e:
            logger.error(e)
            raise NotReadyException("iSCSI initiator IQN file could not be open or might be empty")

    def reset_source_iqn(self):
        '''use in case iqn is invalid and regeneration of it is required'''
        process = self._execute_assert_success([GENERATE_COMMAND])
        iqn = process.get_stdout().decode().strip()
        IQN(iqn)  # validating new IQN
        logger.info("Regeneration of iqn was initiated, old file {}".format(ISCSI_INITIATOR_IQN_FILE) +
                    "had this data in it {!r}, new iqn is:{}".format(self._get_old_iqn(), iqn))
        self.set_source_iqn(iqn)

    def set_source_iqn(self, iqn):
        '''receives a string, validates it's an iqn then set it to the host
        NOTE: this restart the iscsi service and may fail active sessions !
        '''
        IQN(iqn)   # checks iqn is valid
        logger.info("Old IQN was:{}".format(self._get_old_iqn()))
        replacement_strig = 'InitiatorName=' + iqn
        with open(ISCSI_INITIATOR_IQN_FILE, 'w') as fd:
            fd.write(replacement_strig + "\n")
        logger.info("iqn was replaced to {}".format(iqn))
        self._reload_iscsid_service()

    def discover(self, ip_address, port=3260):
        '''initiate discovery and returns a list of dicts which contain all available targets
        '''
        args = ['iscsiadm', '-m', 'discovery', '-t', 'st', '-p', str(ip_address) + ':' + str(port)]
        logger.info("running {}".format(args))
        self._execute_assert_success(args)

        discovery_endpoint = base.Endpoint(ip_address, port)
        targets = self.get_discovered_targets()
        return [target for target in targets if discovery_endpoint in target.get_endpoints()][0]

    def login(self, target, endpoint, auth=None, num_of_connections=1):
        if auth is None:
            auth = iscsiapi_auth.NoAuth()
        self._set_auth(auth, target)
        if self._session_already_active(target, endpoint) is None:
            args = ['iscsiadm', '-m', 'node', '-l', '-T', target.get_iqn(), '-p',
            "{}:{}".format(endpoint.get_ip_address(), endpoint.get_port())]
            self._execute_assert_success(args)
        for session in self._get_sessions_from_sysfs():
            if session.get_target_endpoint() == endpoint:
                return session

    def login_all(self, target, auth=None):
        for endpoint in target.get_endpoints():
            self.login(target, endpoint, auth)
        return self.get_sessions(target=target)

    def logout(self, session):
        ip_address = session.get_target_endpoint().get_ip_address()
        self._execute((['iscsiadm', '-m', 'node', '-u', '-T', str(session.get_target().get_iqn()), '-p', ip_address]))

    def logout_all(self, target):
        self._execute((['iscsiadm', '-m', 'node', '-u', '-T', str(target.get_iqn())]))

    def get_sessions(self, target=None):
        '''receive a target or None and return a list of all available sessions
        '''
        sessions = self._get_sessions_from_sysfs()
        if not target:
            return sessions
        return [session for session in sessions if session.get_target_endpoint() in target.get_endpoints()]

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
        platform = get_platform_string()
        if any(dist in platform for dist in ('redhat', 'centos', 'oracle')):
            pkgmgr = infi.pkgmgr.get_package_manager()
            return pkgmgr.is_package_installed('iscsi-initiator-utils')
        if any(dist in platform for dist in ('ubuntu', 'suse')):
            pkgmgr = infi.pkgmgr.get_package_manager()
            return pkgmgr.is_package_installed('open-iscsi')

    def install(self):
        platform = get_platform_string()
        if any(dist in platform for dist in ('redhat', 'centos', 'oracle')):
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.install_package('iscsi-initiator-utils')
        if any(dist in platform for dist in ('ubuntu', 'suse')):
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.install_package('open-iscsi')
            if 'suse-12' in platform:
                self._execute(['service', 'iscsid', 'start'])

    def uninstall(self):
        platform = get_platform_string()
        if any(dist in platform for dist in ('redhat', 'centos', 'oracle')):
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.remove_package('iscsi-initiator-utils')
        if any(dist in platform for dist in ('ubuntu', 'suse')):
            pkgmgr = infi.pkgmgr.get_package_manager()
            pkgmgr.remove_package('open-iscsi')
