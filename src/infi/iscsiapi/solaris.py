from infi.execute import execute_assert_success, execute
from . import auth as iscsiapi_auth
from . import base
from infi.dtypes.iqn import IQN
from infi.os_info import get_platform_string

from logging import getLogger
logger = getLogger(__name__)

class SolarisISCSIapi(base.ConnectionManager):
    def _execute_assert_n_log(self, cmd, log_prefix='running: ', log_level='debug'):
        try:
            getattr(logger, str(log_level))(log_prefix + "{}".format(cmd if isinstance(cmd, basestring) else ' '.join(cmd)))
        except AttributeError as e:
            logger.error("logger.{} doesn't exist, {!r}".format(log_level, e))
        return execute_assert_success(cmd)

    def _execute_n_log(self, cmd, log_prefix='running: ', log_level='debug'):
        try:
            getattr(logger, str(log_level))(log_prefix + (cmd if isinstance(cmd, basestring) else ' '.join(cmd)))
        except AttributeError as e:
            logger.error("logger.{} doesn't exist, {!r}".format(log_level, e))
        return execute(cmd)

    def _set_number_of_connection_to_infinibox(self):
        '''In Solaris we need to configure in advance how many session an initiator can open.
        This to each target
        '''
        #  Not being used anymore due to INFINIBOX-24755
        con_number = self._how_many_connections_should_be_configured()
        logger.info("Changing number of sessions to {}".format(con_number))
        cmd = ['iscsiadm', 'modify', 'initiator-node', '-c', str(con_number)]
        self._execute_assert_n_log(cmd)

    def _how_many_connections_should_be_configured(self):
        max_endpoints = len(self.get_discovered_targets()[0].get_endpoints())
        for target in self.get_discovered_targets():
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
        output = process.get_stdout().splitlines()
        for line_number, line in enumerate(output):
            if re.search(r'Target name:', line):
                if re.search(r'Target address:', output[line_number + 1]):
                    regex = re.compile(r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)')
                    session = regex.search(output[line_number + 1]).groupdict()
                    session['iqn'] = line.split()[2]
                availble_targets.append(session)
        return availble_targets

    def _parse_discovery_address(self, iqn):
        '''get an iqn of discovered target and return the discovery ip address
        '''
        # TODO: support multiple discovery addresses
        import re
        discovery_addresses = []
        _ = IQN(iqn)  # make sure it's valid iqn
        cmd = ['iscsiadm', 'list', 'discovery-address']
        process = self._execute_assert_n_log(cmd)
        regex = re.compile('Discovery Address: 'r'(?P<ip>\d+\.\d+\.\d+\.\d+)\:(?P<port>\d+)')
        for line in process.get_stdout().splitlines():
            discovery_addresses.append(regex.search(line).groupdict()['ip'])
        for path in self._parse_discovered_targets():
            if path['iqn'] == iqn:
                if path['dst_ip'] in discovery_addresses:
                    return (path['dst_ip'], path['dst_port'])

    def _parse_availble_sessions(self):
        import re
        availble_sessions = []
        cmd = ['iscsiadm', 'list', 'target', '-v']
        process = self._execute_assert_n_log(cmd)
        output = process.get_stdout().splitlines()
        logger.debug([line.strip() for line in output])
        for line_number, line in enumerate(output):
            if re.search(r'Target: ', line):
                iqn = line.split()[1]
                _ = IQN(iqn)  # make sure iqn is valid
                for ident_line in range(1, len(output)):
                    if re.search(r'TPGT:', output[line_number + ident_line]):
                        uid = output[line_number + ident_line].split()[1]
                    source_ip_regex = re.compile('IP address \(Local\): 'r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)\:(?P<src_port>\d+)')
                    target_ip_regex = re.compile('IP address \(Peer\): 'r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\:(?P<dst_port>\d+)')
                    if source_ip_regex.search(output[line_number + ident_line]):
                        session = source_ip_regex.search(output[line_number + ident_line]).groupdict()
                    if target_ip_regex.search(output[line_number + ident_line]):
                        session.update(target_ip_regex.search(output[line_number + ident_line]).groupdict())
                        session['iqn'] = iqn
                        session['uid'] = uid
                        availble_sessions.append(session)
                        break
                    if re.search('Login Parameters', output[line_number + ident_line]):
                        # max search - no point searching after here
                        break
        return availble_sessions

    def get_discovered_targets(self):
        iqn_list = []
        targets = []
        for connectivity in self._parse_discovered_targets():
            iqn_list.append(connectivity['iqn'])
        uniq_iqn = list(set(iqn_list))
        for iqn in uniq_iqn:
            endpoints = []
            if self._parse_discovery_address(iqn) is None:
                continue
            ip_address, port = self._parse_discovery_address(iqn)
            discovery_endpoint = base.Endpoint(ip_address, port)
            for connectivity in self._parse_discovered_targets():
                if connectivity['iqn'] == iqn:
                    endpoints.append(base.Endpoint(connectivity['dst_ip'], connectivity['dst_port']))
            targets.append(base.Target(endpoints, discovery_endpoint, iqn))
        return targets

    def get_source_iqn(self):
        '''return infi.dtypes.iqn type iqn if iscsi initiator file exists
        '''
        import re
        process = self._execute_assert_n_log(['iscsiadm', 'list', 'initiator-node'])
        iqn_line = process.get_stdout().splitlines()[0]
        if re.search(r'Initiator node name', iqn_line):
            iqn = iqn_line.split('Initiator node name: ')[1]
            return IQN(iqn)  # Validate iqn is legal
        else:
            raise RuntimeError("Couldn't find IQN from iscsiadm output, got {!r}".format(process.get_stdout()))

    def reset_source_iqn(self):
        pass

    def set_source_iqn(self, iqn):
        '''receives a string, validates it's an iqn then set it to the host
        NOTE: this restart the iscsi service and may fail active sessions !
        in Solaris, this doesn't save a copy of the old IQN
        '''
        _ = IQN(iqn)   # checks iqn is valid
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

        for line in self._execute_assert_n_log(['iscsiadm', 'list', 'target-param']).get_stdout().splitlines():
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
        endpoints = []
        self._modify_initiator('--authentication', 'none')
        args = ['iscsiadm', 'add', 'discovery-address', str(ip_address) + ':' + str(port)]
        self._execute_assert_n_log(args)
        for target_connectivity in self._parse_discovered_targets():
            if target_connectivity['dst_ip'] == ip_address:
                iqn = target_connectivity['iqn']
                break
        else:
            raise DiscoveryFailed()
        for target_connectivity in self._parse_discovered_targets():
            if iqn == target_connectivity['iqn']:
                endpoints.append(base.Endpoint(target_connectivity['dst_ip'], target_connectivity['dst_port']))
        return base.Target(endpoints, base.Endpoint(ip_address, port), iqn)

    def undiscover(self, target=None):
        '''logout from everything and delete all discovered target if target=None otherwise delete only the target
        discovery endpoints
        '''
        import re
        if target:
            ip_address = target.get_discovery_endpoint().get_ip_address()
            self._execute_n_log(['iscsiadm', 'remove', 'discovery-address', ip_address])
        else:
            cmd = ['iscsiadm', 'list', 'discovery-address']
            process = self._execute_assert_n_log(cmd)
            regex = re.compile('Discovery Address: 'r'(?P<ip>\d+\.\d+\.\d+\.\d+)\:(?P<port>\d+)')
            for line in process.get_stdout().splitlines():
                self._execute_n_log(['iscsiadm', 'remove', 'discovery-address', regex.search(line).groupdict()['ip']])

    def login(self, target, endpoint, auth=None, num_of_connections=1):
        raise NotImplemented("In Solaris login is supported only to all available endpoints\n" +
                             "Therefore, login to a single endpoint couldn't be implemented")

    def login_all(self, target, auth=None):
        if auth is None:
            auth = iscsiapi_auth.NoAuth()
        logger.info("login_all in Solaris login to all available Targets !")
        logger.warn("Performing login in Solaris disconnect momentarily all previous sessions from all targets")
        self._set_auth(auth, target.get_iqn())
        self._disable_iscsi_auto_login()
        self._enable_iscsi_auto_login()
        return self.get_sessions(target=target)

    def logout(self, session):
        raise NotImplemented("Logout from a single session isn't supported in Solaris")

    def logout_all(self, target):
        logger.warn("Performing logout in Solaris disconnect momentarily all sessions from all targets")
        self.undiscover(target)
        self._disable_iscsi_auto_login()
        self._enable_iscsi_auto_login()

    def get_sessions(self, target=None):
        '''receive a target or None and return a list of all available sessions
        '''
        # TODO: add HCT to session
        def get_sessions_for_target(target):
            from infi.dtypes.hctl import HCT
            target_sessions = []
            for session in self._parse_availble_sessions():
                if session['iqn'] == target.get_iqn():
                    hct = HCT(session['src_ip'], 0, session['dst_ip'])
                    target_sessions.append(base.Session(target, base.Endpoint(session['dst_ip'], session['dst_port']),
                                 session['src_ip'], self.get_source_iqn(), session['uid'], hct))
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
