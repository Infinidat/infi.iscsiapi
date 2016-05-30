from infi.win32service import ServiceControlManagerContext
from infi.execute import execute_assert_success, execute, ExecutionError
from . import base
from infi.dtypes.iqn import IQN
from infi.wmi import WmiClient

from logging import getLogger
logger = getLogger(__name__)


class WindowsISCSIapi(base.ConnectionManager):

    def __init__(self, *args, **kwargs):
        super(WindowsISCSIapi, self).__init__(*args, **kwargs)
        self._initiator = None

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
        query = list(client.execute_query("SELECT * FROM MSIscsiInitiator_MethodClass"))[0]
        query.ExecMethod_('RefreshTargetList', None)

    def _execute_discover(self, ip_address, port):
        try:
            execute_assert_success(['iscsicli', 'AddTargetPortal', str(ip_address), str(port)])
        except ExecutionError as e:
            msg = "couldn't connect to ip_address {!r}, error: {!r}" + \
                  "This could be due to one of the following reasons:" + \
                  "1. there is no IP connectivity between your host and {!r}" + \
                  "2. the iSCSI server is down"
            logger.error(msg.format(ip_address, e, ip_address))
            raise

    def _return_target(self, ip_address, outbound_chap, inbound_chap):
        # TODO return endpoint discovery and not ip
        endpoints = []
        iqn = None
        for session in self._get_connectivity_using_wmi():
            endpoints.append(base.Endpoint(session['dst_ip'], session['dst_port']))
            if session['dst_ip'] == ip_address:
                iqn = IQN(session['iqn'])
        if iqn is None:
            raise RuntimeError("iqn is empty, it means that the discovery address {} didn't returned from the target"
                               .format(ip_address))
        return base.Target(endpoints, inbound_chap, outbound_chap, ip_address, iqn)

    def discover(self, ip_address, port=3260, outbound_chap=None, inbound_chap=None):
        '''perform an iscsi discovery to an ip address
        '''
        # TODO: support chap
        # should I save all the discovery portals ?
        # right now ( win 2008 ) WMI doesn't support rescan so we are using cli
        self._create_initiator_obj_if_needed()
        already_discoverd = False
        for target in self.get_discovered_targets():
            if target.get_discovery_endpoint() == ip_address:
                already_discoverd = True
                break
        if not already_discoverd:
            self._execute_discover(ip_address, port)
        return self._return_target(ip_address, outbound_chap, inbound_chap)

    def login(self, target, endpoint, num_of_connections=1):
        '''receives target and endpoint and login to it
        '''
        # TODO limit amount of connections to 32
        # Due to a bug only in 2008 multiple sessions isn't handled ok unless initiator name is monitored
        # Therefore we don't use Qlogin, Details:
        # https://social.technet.microsoft.com/Forums/office/en-US/4b2420d6-0f28-4d12-928d-3920896f582d/iscsi-initiator-target-not-reconnecting-on-reboot?forum=winserverfiles
        # iscsicli LoginTarget <TargetName> <ReportToPNP>
        #              <TargetPortalAddress> <TargetPortalSocket>
        #              <InitiatorInstance> <Port number> <Security Flags>
        #             <Login Flags> <Header Digest> <Data Digest>
        #             <Max Connections> <DefaultTime2Wait>
        #             <DefaultTime2Retain> <Username> <Password> <AuthType> <Key>
        #             <Mapping Count> <Target Lun> <OS Bus> <Os Target>
        #             <OS Lun> ...
        args = ['iscsicli', 'LoginTarget', str(target.get_iqn()), 't',
                endpoint.get_ip_address(), str(endpoint.get_port()),
                self._initiator.get_initiator_name(), '*', '0', '2', '*', '0',
                '*', '0', '0', '*', '*', '0', '0', '0']
        logger.info("running iscsicli LoginTarget {!r}".format(' '.join(args)))
        # TODO: check if session is active if yes then not fail
        # make session with full features ( chap )
        process = execute(args)
        if int(process.get_returncode()) != 0:
            logger.info("couldn't login to {!r} {!r} {!r} because: {!r}"
                        .format(target.get_iqn(), endpoint.get_ip_address(), endpoint.get_port(), process.get_stdout()))
            if "target has already been logged in" not in process.get_stdout():
                raise RuntimeError(process.get_stdout())

        for session in self.get_sessions():
            if session.get_target_endpoint().get_ip_address() == endpoint.get_ip_address():
                return base.Session(endpoint, session.get_source_ip(), self._initiator.get_iqn(), session.get_uid())

    def login_all(self, target):
        ''' login to all endpoint of a target and return the session it achieved
        '''
        for endpoint in target.get_endpoints():
            self.login(target, endpoint)
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

        client = WmiClient('root\\wmi')
        query = client.execute_query('SELECT * FROM MSIscsiInitiator_MethodClass')
        iqn = list(query)[0].Properties_.Item("ISCSINodeName").Value
        return IQN(iqn)

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
            for portal in target.Properties_.Item('PortalGroups').Value[0].Properties_.Item('Portals').Value:
                target_connectivity = {'dst_ip':portal.Properties_.Item('Address').Value,
                                       'dst_port': portal.Properties_.Item('Port').Value, 'iqn': iqn}
                if target_connectivity not in availble_targets_connectivity:
                    availble_targets_connectivity.append(target_connectivity)
        return availble_targets_connectivity

    def get_discovered_targets(self):
        '''return a list of discovered target objects
        '''
        # TODO add chap support
        self._refresh_wmi_db()
        import re
        discovered_targets = []
        client = WmiClient('root\\wmi')
        for query in client.execute_query('SELECT * from  MSIscsiInitiator_TargetClass'):
            endpoints = []
            iqn = query.Properties_.Item('TargetName').Value
            for portal in query.Properties_.Item('PortalGroups').Value[0].Properties_.Item('Portals').Value:
                endpoint = base.Endpoint(portal.Properties_.Item('Address').Value, portal.Properties_.Item('Port').Value)
                if endpoint not in endpoints:
                    endpoints.append(endpoint)

            regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            discovery_endpoint = re.findall(regex, query.Properties_.Item('DiscoveryMechanism').Value)
            if discovery_endpoint == []:
                raise RuntimeError("couldn't find an expected wmi object")
            target = base.Target(endpoints, None, None, discovery_endpoint[0], iqn)
            if target not in discovered_targets:
                discovered_targets.append(target)
        return discovered_targets

    def get_sessions(self, target=None):
        '''receive a target or None and return a list of all available sessions
        '''
        # assumes only one connection over each session ( conn_0 ) 3.0 Infinibox limit
        self._refresh_wmi_db()
        def _get_sessions_of_target(target):
            client = WmiClient('root\\wmi')
            wql = "SELECT * from MSiSCSIInitiator_SessionClass where TargetName='%s'" % str(target.get_iqn())
            query = client.execute_query(wql)
            target_sessions = []
            for session in query:
                uid = session.Properties_.Item('SessionId').Value
                conn_0 = list(session.Properties_.Item('ConnectionInformation').Value)[0]
                source_ip = conn_0.Properties_.Item('InitiatorAddress').Value
                source_iqn = session.Properties_.Item('InitiatorName').Value
                target_address = conn_0.Properties_.Item('TargetAddress').Value
                target_port = conn_0.Properties_.Item('TargetPort').Value
                target_sessions.append(base.Session(base.Endpoint(target_address, target_port), source_ip, source_iqn, uid))
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
        logger.info("you just ran iscsi rescan, in windows it does nothing")
        return

    def undiscover(self, target=None):
        '''delete all discovered sessions or only iqn specific active sessions
        '''
        for session in self._get_connectivity_using_wmi():
            args = ['iscsicli', 'RemoveTargetPortal', str(session['dst_ip']), str(session['dst_port'])]
            if not target:
                logger.info("running {}".format(args))
                execute(args)
            elif target.get_iqn() == session['iqn']:
                logger.info("running {}".format(args))
                execute(args)
        self._refresh_wmi_db()

class MicrosoftSoftwareInitiator(base.SoftwareInitiator):

    def is_installed(self):
        '''in windows return True if iSCSI initiator sw is running otherwise return False
        '''
        with ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                return service.is_running()

    def install(self):
        '''start the iSCSI service on windows.
           in the future will also autostart the service
        '''
        logger.debug("trying to start service MSiSCSI")
        with ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                logger.debug("starting service MSiSCSI")
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
