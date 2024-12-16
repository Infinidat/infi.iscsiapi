from __future__ import unicode_literals


import six

from infi.execute import execute_assert_success, execute
from infi.pyutils.lazy import cached_method, clear_cache
from . import auth as iscsiapi_auth
from . import base
from infi.dtypes.iqn import IQN
from infi.os_info import get_platform_string

from logging import getLogger
logger = getLogger(__name__)


class SolarisISCSIapi(base.ConnectionManager):
    def _execute_assert_n_log(self, cmd, log_prefix='running: ', log_level='debug'):
        try:
            getattr(logger, str(log_level))(log_prefix + "{}".format(
                cmd if isinstance(cmd, six.string_types) else ' '.join(cmd)))
        except AttributeError as e:
            logger.error("logger.{} doesn't exist, {!r}".format(log_level, e))
        return execute_assert_success(cmd)

    def _execute_n_log(self, cmd, log_prefix='running: ', log_level='debug'):
        try:
            getattr(logger, str(log_level))(
                log_prefix + (cmd if isinstance(cmd, six.string_types) else ' '.join(cmd)))
        except AttributeError as e:
            logger.error("logger.{} doesn't exist, {!r}".format(log_level, e))
        return execute(cmd)

    def _set_number_of_connection_to_infinibox(self, target):
        '''In Solaris we need to configure in advance how many session an initiator can open.
        This to each target
        '''
        connections = 1
        discovered_targets = self.get_discovered_targets()
        for discovered_target in discovered_targets:
            if discovered_target.get_iqn() == target.get_iqn():
                connections = len(discovered_target.get_endpoints())
                break
        logger.info('Changing number of iSCSI sessions for target %s to %s', target.get_iqn(), connections)
        cmd = ['iscsiadm', 'modify', 'target-param', '-c', str(connections), str(target.get_iqn())]
        self._execute_assert_n_log(cmd)

    def _how_many_connections_should_be_configured(self):
        # needs rewrite if used ( 4.0 ), need to verify that first target is infinibox()
        discovered_targets = self.get_discovered_targets()
        max_endpoints = len(discovered_targets[0].get_endpoints())
        for target in discovered_targets:
            if max_endpoints < len(target.get_endpoints()):
                max_endpoints = len(target.get_endpoints())
        return max_endpoints

    def _parse_discovered_targets(self):
        import re
        availble_targets = []
        cmd = ['iscsiadm', 'list', 'discovery-address']
        process = self._execute_assert_n_log(cmd)
        if len(list(process.get_stdout())) == 0:
            return availble_targets
        cmd = ['iscsiadm', 'list', 'discovery-address', '-v']
        process = self._execute_n_log(cmd)
        if process.get_returncode() != 0:
            return availble_targets
        output = process.get_stdout().decode().splitlines()
        for line_number, line in enumerate(output):
            if re.search(r'Target name:', line):
                if re.search(r'Target address:', output[line_number + 1]):
                    regex = re.compile(r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)')
                    session = regex.search(output[line_number + 1]).groupdict()
                    session['iqn'] = line.split()[2]
                availble_targets.append(session)
        return availble_targets

    def _parse_discovery_address(self, iqn, discovered_targets):
        '''get an iqn of discovered target and return the discovery ip address
        '''
        # TODO: support multiple discovery addresses
        import re
        discovery_addresses = []
        IQN(iqn)  # make sure it's valid iqn
        cmd = ['iscsiadm', 'list', 'discovery-address']
        process = self._execute_assert_n_log(cmd)
        regex = re.compile('Discovery Address: 'r'(?P<ip>\d+\.\d+\.\d+\.\d+)\:(?P<port>\d+)')
        for line in process.get_stdout().decode().splitlines():
            discovery_addresses.append(regex.search(line).groupdict()['ip'])
        for targets in discovered_targets:
            if targets['iqn'] == iqn:
                if targets['dst_ip'] in discovery_addresses:
                    return (targets['dst_ip'], targets['dst_port'])

    def _parse_availble_sessions(self):
        import re
        availble_sessions = []
        cmd = ['iscsiadm', 'list', 'target', '-v']
        process = self._execute_assert_n_log(cmd)
        output = process.get_stdout().decode().splitlines()
        logger.debug([line.strip() for line in output])
        source_ip_regex = re.compile('IP address \(Local\): 'r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\:(?P<src_port>\d+)')
        target_ip_regex = re.compile('IP address \(Peer\): 'r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)')
        for line_number, line in enumerate(output):
            if 'Target: ' in line:
                iqn = line.split()[1]
                IQN(iqn)  # make sure iqn is valid
                for ident_line in range(line_number, len(output)):
                    if 'ISID: ' in output[ident_line]:
                        uid = output[ident_line].split()[1]
                    if source_ip_regex.search(output[ident_line]):
                        session = source_ip_regex.search(output[ident_line]).groupdict()
                    if target_ip_regex.search(output[ident_line]):
                        session.update(target_ip_regex.search(output[ident_line]).groupdict())
                        session['iqn'] = iqn
                        session['uid'] = uid
                        availble_sessions.append(session)
                        break
                    if re.search('Login Parameters', output[ident_line]):
                        # max search - no point searching after here
                        break
        return availble_sessions

    @cached_method
    def get_discovered_targets(self):
        iqns = []
        targets = []
        discovered_targets = self._parse_discovered_targets()
        for target in discovered_targets:
            iqns.append(target['iqn'])
        iqns = list(set(iqns))
        for iqn in iqns:
            endpoints = []
            host_port = self._parse_discovery_address(iqn, discovered_targets)
            if host_port is None:
                continue
            host, port = host_port
            endpoint = base.Endpoint(host, port)
            for target in discovered_targets:
                if target['iqn'] == iqn:
                    endpoints.append(base.Endpoint(target['dst_ip'], target['dst_port']))
            targets.append(base.Target(endpoints, endpoint, iqn))
        return targets

    @cached_method
    def get_source_iqn(self):
        '''return infi.dtypes.iqn type iqn if iscsi initiator file exists
        '''
        import re
        process = self._execute_assert_n_log(['iscsiadm', 'list', 'initiator-node'])
        process_stdout = process.get_stdout().decode()
        iqn_line = process_stdout.splitlines()[0]
        if re.search(r'Initiator node name', iqn_line):
            iqn = iqn_line.split('Initiator node name: ')[1]
            return IQN(iqn)  # Validate iqn is legal
        else:
            raise RuntimeError("Couldn't find IQN from iscsiadm output, got {!r}".format(process_stdout))

    def reset_source_iqn(self):
        pass

    def set_source_iqn(self, iqn):
        '''receives a string, validates it's an iqn then set it to the host
        NOTE: this restart the iscsi service and may fail active sessions !
        in Solaris, this doesn't save a copy of the old IQN
        '''
        clear_cache(self)
        IQN(iqn)   # checks iqn is valid
        old_iqn = self.get_source_iqn()  # check file exist and valid
        execute_assert_success(['iscsiadm', 'modify', 'initiator-node', '-N', iqn])
        logger.info("iqn was replaced from {} to {}".format(old_iqn, iqn))

    def _enable_iscsi_auto_login(self):
        cmd = ['iscsiadm', 'modify', 'discovery', '--sendtargets', 'enable']
        return self._execute_assert_n_log(cmd)

    def _disable_iscsi_auto_login(self):
        cmd = ['iscsiadm', 'modify', 'discovery', '--sendtargets', 'disable']
        return self._execute_assert_n_log(cmd)

    def _modify_target(self, key, value, iqn):
        cmd = ['iscsiadm', 'modify', 'target-param', key, value, str(iqn)]
        self._execute_assert_n_log(cmd)

    def _modify_initiator(self, key, value):
        cmd = ['iscsiadm', 'modify', 'initiator-node', key, value]
        self._execute_assert_n_log(cmd)

    def _clear_auth(self):
        cmd = ['iscsiadm', 'modify', 'initiator-node', '--authentication', 'none']
        self._execute_assert_n_log(cmd)

        for line in self._execute_assert_n_log(['iscsiadm', 'list', 'target-param']).get_stdout().decode().splitlines():
            if not line.startswith('Target'):
                return
            iqn = line.strip().split()[1]
            self._modify_target('--bi-directional-authentication', 'disable', iqn)
            self._modify_target('--authentication', 'none', iqn)

    def _chap_set_password(self, cmd, password):
        # Solaris support chap pass of 12-16 characters
        # potiontal bug when password reset doesn't work
        import pexpect
        from infi.iscsiapi.iscsi_exceptions import ChapPasswordTooLong
        if len(password) > 16:
            raise ChapPasswordTooLong()
        logger.debug("running: {}".format(cmd))
        process = pexpect.spawn(cmd)
        process.expect("Enter secret:")
        process.sendline(password)
        process.expect("Re-enter secret:")
        process.sendline(password)
        logger.debug("password reset finished with exit code {}".format(process.exitstatus))

    def _set_auth(self, auth, iqn):
        def _set_unidirectional_chap():
            self._modify_target('--bi-directional-authentication', 'disable', iqn)
            self._modify_target('--authentication', 'chap', iqn)
            self._modify_initiator('--CHAP-name', auth.get_inbound_username())
            self._chap_set_password('iscsiadm modify initiator-node --CHAP-secret', auth.get_inbound_secret())

        def _set_bidirectional_chap():
            self._modify_target('--bi-directional-authentication', 'enable', iqn)
            self._modify_target('--CHAP-name', auth.get_outbound_username(), iqn)
            cmd = 'iscsiadm modify target-param --CHAP-secret {}'.format(iqn)
            self._chap_set_password(cmd, auth.get_outbound_secret())

        if isinstance(auth, iscsiapi_auth.ChapAuth):
            _set_unidirectional_chap()
        elif isinstance(auth, iscsiapi_auth.MutualChapAuth):
            _set_unidirectional_chap()
            _set_bidirectional_chap()
        elif isinstance(auth, iscsiapi_auth.NoAuth):
            self._modify_target('--bi-directional-authentication', 'disable', iqn)
            self._modify_target('--authentication', 'none', iqn)

    def discover(self, ip_address, port=3260):
        '''initiate discovery and returns a list of dicts which contain all available targets
        '''
        from .iscsi_exceptions import DiscoveryFailed
        clear_cache(self)
        endpoints = []
        self._modify_initiator('--authentication', 'none')
        args = ['iscsiadm', 'add', 'discovery-address', str(ip_address) + ':' + str(port)]
        self._execute_assert_n_log(args)
        discovered_targets = self._parse_discovered_targets()
        for target in discovered_targets:
            if target['dst_ip'] == ip_address:
                iqn = target['iqn']
                break
        else:
            raise DiscoveryFailed()
        for target in discovered_targets:
            if iqn == target['iqn']:
                endpoints.append(base.Endpoint(target['dst_ip'], target['dst_port']))
        return base.Target(endpoints, base.Endpoint(ip_address, port), iqn)

    def undiscover(self, target=None):
        '''logout from everything and delete all discovered target if target=None otherwise delete only the target
        discovery endpoints
        '''
        import re
        clear_cache(self)
        if target:
            ip_address = target.get_discovery_endpoint().get_ip_address()
            self._execute_n_log(['iscsiadm', 'remove', 'discovery-address', ip_address])
        else:
            cmd = ['iscsiadm', 'list', 'discovery-address']
            process = self._execute_assert_n_log(cmd)
            regex = re.compile('Discovery Address: 'r'(?P<ip>\d+\.\d+\.\d+\.\d+)\:(?P<port>\d+)')
            for line in process.get_stdout().decode().splitlines():
                self._execute_n_log(['iscsiadm', 'remove', 'discovery-address', regex.search(line).groupdict()['ip']])

    def login(self, target, endpoint, auth=None, num_of_connections=1):
        raise NotImplemented("In Solaris login is supported only to all available endpoints\n" +
                             "Therefore, login to a single endpoint couldn't be implemented")

    def login_all(self, target, auth=None):
        clear_cache(self)
        if auth is None:
            auth = iscsiapi_auth.NoAuth()
        logger.info("login_all in Solaris login to all available Targets !")
        logger.warn("Performing login in Solaris disconnect momentarily all previous sessions from all targets")
        self._set_number_of_connection_to_infinibox(target)
        self._set_auth(auth, target.get_iqn())
        self._disable_iscsi_auto_login()
        self._enable_iscsi_auto_login()
        return self.get_sessions(target=target)

    def logout(self, session):
        raise NotImplemented("Logout from a single session isn't supported in Solaris")

    def logout_all(self, target):
        clear_cache(self)
        logger.warn("Performing logout in Solaris disconnect momentarily all sessions from all targets")
        self.undiscover(target)
        self._disable_iscsi_auto_login()
        self._enable_iscsi_auto_login()

    @cached_method
    def get_sessions(self, target=None):
        '''receive a target or None and return a list of all available sessions
        '''
        # TODO: add HCT to session
        iqn = self.get_source_iqn()
        availble_sessions = self._parse_availble_sessions()
        def get_sessions_for_target(target):
            from infi.dtypes.hctl import HCT
            target_sessions = []
            for session in availble_sessions:
                if session['iqn'] == target.get_iqn():
                    hct = HCT(session['src_ip'], 0, session['dst_ip'])
                    target_sessions.append(base.Session(target, base.Endpoint(session['dst_ip'], session['dst_port']),
                                 session['src_ip'], iqn, session['uid'], hct))
            return target_sessions

        if target:
            return get_sessions_for_target(target)
        else:
            sessions = []
            targets = self.get_discovered_targets()
            for target in targets:
                sessions.extend(get_sessions_for_target(target))
            return sessions

    def rescan(self):
        '''does nothing in Solaris
        '''
        logger.info("Someone just initiated iscsi rescan, In Solaris it does nothing")
        pass


class SolarisSoftwareInitiator(base.SoftwareInitiator):
    def is_installed(self):
        ''' Return True if iSCSI initiator sw is installed otherwise return False
        '''
        if 'solaris' in get_platform_string():
            process1 = execute('pkginfo', '-q', 'SUNWiscsir')
            process2 = execute('pkginfo', '-q', 'SUNWiscsiu')
            if process1.get_returncode() == process2.get_returncode() == 0:
                return True
            else:
                return False

    def install(self):
        # Not installing iscsi utils on solaris suppose to come by default
        pass

    def uninstall(self):
        # Does nothing, not implemented in pkgmgr
        pass
