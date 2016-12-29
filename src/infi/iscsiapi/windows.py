from infi.win32service import ServiceControlManagerContext
from infi.execute import execute_assert_success, execute, ExecutionError
from . import base
from . import auth as iscsiapi_auth
from infi.dtypes.iqn import IQN
from infi.wmi import WmiClient

from logging import getLogger
from time import sleep
logger = getLogger(__name__)

ISCSI_LOGIN_FLAG_MULTIPATH_DISABLED = 0
ISCSI_LOGIN_FLAG_REQUIRE_IPSEC = 1
ISCSI_LOGIN_FLAG_MULTIPATH_ENABLED = 2
ISCSI_NO_AUTH_TYPE = 0
ISCSI_CHAP_AUTH_TYPE = 1
ISCSI_MUTUAL_CHAP_AUTH_TYPE = 2
ISCSI_SECURITY_TUNNEL_MODE_PREFERRED = 0x00000040
ISCSI_SECURITY_TRANSPORT_MODE_PREFERRED = 0X00000020
ISCSI_SECURITY_PFS = 0x00000010
ISCSI_SECURITY_NEGOTIATE_VIA_AGGRESSIVE_MODE = 0x00000008
ISCSI_SECURITY_NEGOTIATE_VIA_MAIN_MODE = 0x00000004
ISCSI_SECURITY_IPSEC_ENABLED = 0x00000002
ISCSI_SECURITY_VALID_FLAGS = 1


class WindowsISCSIapi(base.ConnectionManager):
    def __init__(self):
        super(WindowsISCSIapi, self).__init__()
        self._initiator = None
        self._login_flags = ISCSI_LOGIN_FLAG_MULTIPATH_ENABLED
        self._security_flags = 0

    def disable_mpio(self):
        self._login_flags = ISCSI_LOGIN_FLAG_MULTIPATH_DISABLED

    def enable_mpio(self):
        self._login_flags = ISCSI_LOGIN_FLAG_MULTIPATH_ENABLED

    def _create_initiator_obj_if_needed(self):
        if not self._initiator:
            iscsi_software = MicrosoftSoftwareInitiator()
            if not iscsi_software.is_installed():
                raise RuntimeError("iscsi sw isn't running")
            client = WmiClient('root\\wmi')
            query = client.execute_query('SELECT * from MSIscsiInitiator_InitiatorClass')
            initiator_name = list(query)[0].Properties_.Item('InitiatorName').Value
            iqn = self.get_source_iqn()
            self._initiator = base.Initiator(iqn, initiator_name)

    def _refresh_wmi_db(self):
        client = WmiClient('root\\wmi')
        for item in client.execute_query("SELECT * FROM MSIscsiInitiator_MethodClass"):
            item.ExecMethod_('RefreshTargetList', None)

    def _execute_discover(self, ip_address, port):
        from .iscsi_exceptions import DiscoveryFailed
        try:
            execute_assert_success(['iscsicli', 'AddTargetPortal', str(ip_address), str(port)])
        except ExecutionError as e:
            msg = "couldn't connect to ip_address {!r}, error: {!r}" + \
                  "This could be due to one of the following reasons:" + \
                  "1. There is no IP connectivity between your host and {!r}" + \
                  "2. The iSCSI server is down"
            formated_msg = msg.format(ip_address, e, ip_address)
            logger.error(formated_msg)
            raise DiscoveryFailed(formated_msg)

    def _return_target(self, ip_address, port):
        endpoints = []
        iqn = None
        sessions = self._get_connectivity_using_wmi()
        for session in sessions:
            if session['dst_ip'] == ip_address:
                iqn = IQN(session['iqn'])
        if iqn is None:
            raise RuntimeError("iqn is empty, it means that the discovery address {} didn't returned from the target"
                               .format(ip_address))
        for session in sessions:
            if session['iqn'] == iqn:
                endpoints.append(base.Endpoint(session['dst_ip'], session['dst_port']))
        return base.Target(endpoints, base.Endpoint(ip_address, port), iqn)

    def _get_discovery_endpoints(self):
        '''return all discovery endpoints currently use only for undiscover
        '''
        discovery_endpoints = []
        client = WmiClient('root\\wmi')
        query = client.execute_query('SELECT * FROM  MSiSCSIInitiator_SendTargetPortalClass')
        for discovery_endpoint in query:
            endpoint = base.Endpoint(discovery_endpoint.Properties_.Item('PortalAddress').Value,
            discovery_endpoint.Properties_.Item('PortalPort').Value)
            if endpoint not in discovery_endpoints:
                discovery_endpoints.append(endpoint)
        return discovery_endpoints

    def _return_auth_type(self, auth):
        if isinstance(auth, iscsiapi_auth.ChapAuth):
            return ISCSI_CHAP_AUTH_TYPE
        if isinstance(auth, iscsiapi_auth.MutualChapAuth):
            return ISCSI_MUTUAL_CHAP_AUTH_TYPE
        if isinstance(auth, iscsiapi_auth.NoAuth):
            return ISCSI_NO_AUTH_TYPE

    def discover(self, ip_address, port=3260):
        '''perform an iscsi discovery to an ip address
        '''
        # TODO: support chap
        self._create_initiator_obj_if_needed()
        already_discoverd = False
        discovery_endpoint = base.Endpoint(ip_address, port)
        for target in self.get_discovered_targets():
            if target.get_discovery_endpoint() == discovery_endpoint:
                self._refresh_wmi_db()
                already_discoverd = True
                break
        if not already_discoverd:
            self._execute_discover(ip_address, port)
        return self._return_target(ip_address, port)

    def login(self, target, endpoint, auth=None, num_of_connections=1):
        '''receives target and endpoint and login to it
        '''
        # LoginTarget is not persistent across reboots
        # PersistentLoginTarget will make sure we connect after reboot but not immediately
        # so we need to call both
        if auth is None:
            auth = iscsiapi_auth.NoAuth()
        self._iscsicli_login('LoginTarget', target, endpoint, auth, num_of_connections)
        self._iscsicli_login('PersistentLoginTarget', target, endpoint, auth, num_of_connections)
        for session in self.get_sessions():
            if session.get_target_endpoint() == endpoint:
                return session

    def _iscsicli_login(self, login_command, target, endpoint, auth=None, num_of_connections=1):
        def _remove_outbound_secret():
            cmd = ['iscsicli', 'CHAPSecret', '*']
            execute(cmd)

        auth_type = self._return_auth_type(auth)
        if auth_type == ISCSI_CHAP_AUTH_TYPE:
            username = auth.get_inbound_username()
            password = auth.get_inbound_secret()
            _remove_outbound_secret()
        elif auth_type == ISCSI_MUTUAL_CHAP_AUTH_TYPE:
            username = auth.get_inbound_username()
            password = auth.get_inbound_secret()
            cmd = ['iscsicli', 'CHAPSecret', auth.get_outbound_secret()]
            execute(cmd)
        elif auth_type == ISCSI_NO_AUTH_TYPE:
            username = '*'
            password = '*'
            _remove_outbound_secret()
        # Due to a bug only in 2008 multiple sessions isn't handled ok unless initiator name is monitored
        # Therefore we don't use Qlogin, Details:
        # https://social.technet.microsoft.com/Forums/office/en-US/4b2420d6-0f28-4d12-928d-3920896f582d/iscsi-initiator-target-not-reconnecting-on-reboot?forum=winserverfiles
        # http://download.microsoft.com/download/a/e/9/ae91dea1-66d9-417c-ade4-92d824b871af/uguide.doc

        # iscsicli LoginTarget <TargetName> <ReportToPNP>
        #                      <TargetPortalAddress> <TargetPortalSocket>
        #                      <InitiatorInstance> <Port number> <Security Flags>
        #                     <Login Flags> <Header Digest> <Data Digest>
        #                     <Max Connections> <DefaultTime2Wait>
        #                     <DefaultTime2Retain> <Username> <Password> <AuthType> <Key>
        #                     <Mapping Count> <Target Lun> <OS Bus> <Os Target>
        #                     <OS Lun> ...

        # iscsicli PersistentLoginTarget <TargetName> <ReportToPNP>
        #                      <TargetPortalAddress> <TargetPortalSocket>
        #                     <InitiatorInstance> <Port number> <Security Flags>
        #                     <Login Flags> <Header Digest> <Data Digest>
        #                     <Max Connections> <DefaultTime2Wait>
        #                     <DefaultTime2Retain> <Username> <Password> <AuthType> <Key>
        #                     <Mapping Count> <Target Lun> <OS Bus> <Os Target>
        #                     <OS Lun> ...
        command = '''iscsicli {0} {TargetName} {ReportToPNP}
                {TargetPortalAddress} {TargetPortalSocket}
                {InitiatorInstance} {Port_number} {Security_Flags}
                {Login_Flags} {Header_Digest} {Data_Digest}
                {Max_Connections} {DefaultTime2Wait}
                {DefaultTime2Retain} {Username} {Password} {AuthType} {Key}
                {Mapping_Count}'''

        args = command.format(login_command, TargetName=target.get_iqn(),
                              ReportToPNP='t',  # If the value is T or t then the LUN is exposed as a device
                              TargetPortalAddress=endpoint.get_ip_address(),
                              TargetPortalSocket=endpoint.get_port(),
                              InitiatorInstance=self._initiator.get_initiator_name(),
                              Port_number='*',  # the kernel mode initiator driver chooses the initiator port used
                              Security_Flags=self._security_flags,
                              Login_Flags=self._login_flags,
                              Header_Digest='*',  # the digest setting is determined by the initiator kernel mode driver
                              Data_Digest=0,
                              Max_Connections='*',  # the kernel mode initiator driver chooses the value for maximum connections
                              DefaultTime2Wait=0,
                              DefaultTime2Retain=0,
                              Username=username,  # the iSCSI initiator service will use the initiator node name as the CHAP username
                              Password=password,  # The initiator will use this secret to compute a hash value based on the challenge sent by the target
                              AuthType=auth_type,
                              Key=0,
                              Mapping_Count=0)
        logger.info("running iscsicli LoginTarget {!r}".format(args))
        process = execute(args.split())
        if int(process.get_returncode()) != 0:
            logger.info("couldn't login to {!r} {!r} {!r} because: {!r}"
                        .format(target.get_iqn(), endpoint.get_ip_address(), endpoint.get_port(), process.get_stdout()))
            if "target has already been logged in" not in process.get_stdout():
                raise RuntimeError(process.get_stdout())

    def login_all(self, target, auth=None):
        ''' login to all endpoint of a target and return the session it achieved
        '''
        if auth is None:
            auth = iscsiapi_auth.NoAuth()
        for endpoint in target.get_endpoints():
            self.login(target, endpoint, auth)
        return self.get_sessions(target=target)

    def logout(self, session):
        '''receive a session and perform an iSCSI logout
        '''
        execute_assert_success(['iscsicli', 'LogoutTarget', str(session.get_uid())])

    def logout_all(self, target):
        '''receive a target and logout of it
        '''
        for session in self.get_sessions(target):
            self.logout(session)

    def get_source_iqn(self):
        from .iscsi_exceptions import NotReadyException
        client = WmiClient('root\\wmi')
        query = list(client.execute_query('SELECT * FROM MSIscsiInitiator_MethodClass'))
        if not query:
            raise NotReadyException("Could not query iSCSI initiator from WMI")
        iqn = query[0].Properties_.Item("ISCSINodeName").Value
        return IQN(iqn)

    def reset_source_iqn(self):
        execute_assert_success(['iscsicli', 'NodeName', '*'])

    def set_source_iqn(self, iqn):
        '''receive an iqn as a string, verify it's valid and set it.
        returns iqn type of the new IQN or None if fails
        '''
        logger.info("iqn before the change is {!r} going to change to {!r}".format(self.get_source_iqn(), iqn))
        _ = IQN(iqn)  # raise if iqn doesn't exist
        client = WmiClient('root\\wmi')
        query = list(client.execute_query("SELECT * FROM MSIscsiInitiator_MethodClass"))[0]
        initiator_name = query.Methods_.Item("SetIscsiInitiatorNodeName")
        parameters = initiator_name.InParameters.SpawnInstance_()
        parameters.Properties_.Item("InitiatorNodeName").Value = iqn
        query.ExecMethod_('SetIscsiInitiatorNodeName', parameters)
        logger.info("iqn is now {!r}".format(self.get_source_iqn()))
        return self.get_source_iqn()

    def _get_connectivity_using_wmi(self):
        '''returns a list of dicts which contain all available targets with it's main parameters
        '''
        availble_targets_connectivity = []
        client = WmiClient('root\\wmi')
        for target in client.execute_query('SELECT * from  MSIscsiInitiator_TargetClass'):
            iqn = target.Properties_.Item('TargetName').Value
            for portal_group in target.Properties_.Item('PortalGroups').Value:
                for portal in portal_group.Properties_.Item('Portals').Value:
                    target_connectivity = {'dst_ip': portal.Properties_.Item('Address').Value,
                                           'dst_port': portal.Properties_.Item('Port').Value, 'iqn': iqn}
                    if target_connectivity not in availble_targets_connectivity:
                        availble_targets_connectivity.append(target_connectivity)
        return availble_targets_connectivity

    def get_discovered_targets(self):
        '''return a list of discovered target objects
        '''
        import re
        logger.info("get_discovered_targets")
        discovered_targets = []
        client = WmiClient('root\\wmi')
        for query in client.execute_query('SELECT * from MSIscsiInitiator_TargetClass'):
            endpoints = []
            iqn = query.Properties_.Item('TargetName').Value
            for portal_group in query.Properties_.Item('PortalGroups').Value:
                for portal in portal_group.Properties_.Item('Portals').Value:
                    endpoint = base.Endpoint(portal.Properties_.Item('Address').Value, portal.Properties_.Item('Port').Value)
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)

            regex = re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\ (?P<port>\d+)')
            discovery_endpoint = regex.search(query.Properties_.Item('DiscoveryMechanism').Value).groupdict()
            if discovery_endpoint == []:
                raise RuntimeError("couldn't find an expected wmi object")
            discovery_endpoint['port'] = int(str(discovery_endpoint['port']), base=10)
            target = base.Target(endpoints,
                                 base.Endpoint(discovery_endpoint['ip'], str(discovery_endpoint['port'])), iqn)
            if target not in discovered_targets:
                discovered_targets.append(target)
        return discovered_targets

    def get_sessions(self, target=None):
        '''receive a target or None and return a list of all available sessions
        '''
        # assumes only one connection over each session ( conn_0 ) 3.0 Infinibox limit
        # TODO: when InfiniBox will support MCS need to modify this code
        from infi.dtypes.hctl import HCT
        logger.info("get_sessions(target={!r}".format(target))
        def _get_sessions_of_target(target, retries=3):
            from .iscsi_exceptions import WMIConnectionInformationMissing
            if not retries:
                raise WMIConnectionInformationMissing()

            client = WmiClient('root\\wmi')
            wql = "SELECT * from MSiSCSIInitiator_SessionClass where TargetName='%s'" % str(target.get_iqn())
            query = client.execute_query(wql)
            target_sessions = []
            for session in query:
                hct = None
                uid = session.Properties_.Item('SessionId').Value
                connections = session.Properties_.Item('ConnectionInformation').Value
                if not connections:
                    sleep(1)
                    return _get_sessions_of_target(target, retries-1)

                conn_0 = connections[0]
                source_ip = conn_0.Properties_.Item('InitiatorAddress').Value
                source_iqn = session.Properties_.Item('InitiatorName').Value
                target_address = conn_0.Properties_.Item('TargetAddress').Value
                target_port = conn_0.Properties_.Item('TargetPort').Value

                if not session.Properties_.Item('Devices').Value:
                    hct = HCT(-1, 0, -1)
                else:
                    devices = list(session.Properties_.Item('Devices').Value)
                    hct = HCT(devices[0].Properties_.Item('ScsiPortNumber').Value,
                              devices[0].Properties_.Item('ScsiPathId').Value,
                              devices[0].Properties_.Item('ScsiTargetId').Value)
                target_sessions.append(base.Session(target, base.Endpoint(target_address, target_port), source_ip, source_iqn, uid, hct))
            return target_sessions

        if target:
            return _get_sessions_of_target(target)
        else:
            sessions = []
            for target in self.get_discovered_targets():
                sessions.extend(_get_sessions_of_target(target))
            return sessions

    def rescan(self):
        '''rescan all available sessions
        '''
        self._refresh_wmi_db()

    def undiscover(self, target=None):
        '''logout and delete all discovered sessions for a target or for all targets
        '''
        if target:
            self.logout_all(target)
            for endpoint in self._get_discovery_endpoints():
                if endpoint in target.get_endpoints():
                    args = ['iscsicli', 'RemoveTargetPortal', str(endpoint.get_ip_address()), str(endpoint.get_port())]
                    logger.info("running {}".format(args))
                    execute(args)
        else:
            for target in self.get_discovered_targets():
                self.logout_all(target)
            for endpoint in self._get_discovery_endpoints():
                args = ['iscsicli', 'RemoveTargetPortal', str(endpoint.get_ip_address()), str(endpoint.get_port())]
                logger.info("running {}".format(args))
                execute(args)
        self._refresh_wmi_db()

class MicrosoftSoftwareInitiator(base.SoftwareInitiator):
    def is_installed(self):
        '''in windows return True if iSCSI initiator sw is running otherwise return False
        '''
        with ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                return service.is_running() and service.is_autostart()

    def install(self):
        '''start the iSCSI service on windows.
           in the future will also autostart the service
        '''
        logger.debug("trying to start service MSiSCSI")
        with ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                logger.debug("starting service MSiSCSI")
                service.start_automatically()
                service.safe_start()
                service.wait_on_pending()

    def uninstall(self):
        '''Stop the iscsi service on windows
        '''
        with ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                logger.debug("stopping MSiSCSI")
                service.safe_stop()
                service.wait_on_pending()
                service.disable()
