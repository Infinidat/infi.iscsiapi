from infi.execute import execute_assert_success, execute, ExecutionError
from .base import ISCSIapi
from ctypes import WinError

from logging import getLogger
logger = getLogger(__name__)

class WindowsISCSIapi(ISCSIapi):

    #from https://msdn.microsoft.com/en-us/library/windows/desktop/bb870791(v=vs.85).aspx
    ISCSI_NO_AUTH_TYPE = 0
    ISCSI_CHAP_AUTH_TYPE = 1
    ISCSI_MUTUAL_CHAP_AUTH_TYPE = 2


    def discover_target(self, ip_adder):
        '''initiate discovery and returns a list of dicts which contain all availble targets
        '''
        # right now ( win 2008 ) WMI doesn't support rescan so we are using cli
        try:
            execute_assert_success(['iscsicli', 'QAddTargetPortal', ip_adder])
        except ExecutionError as e:
            logger.error("couldn't connect to ip_adder {!r}, error: {!r}".format(ip_adder, e))
        return self.get_sessions()

    def login_to_target(self, iqn,  ip=None):
        '''recives an iqn as string and login to it
        '''
        from infi.wmi import WmiClient
        if not ip:
            execute_assert_success(['iscsicli', 'QLoginTarget', iqn])
        else:
            client = WmiClient('root\\wmi')
            for connection in client.execute_query('SELECT * from  MSIscsiInitiator_TargetClass WHERE TargetName={!r}'.format(iqn)):
                method = connection.Methods_.Item("Login")
                parameters = method.InParameters.SpawnInstance_()
                parameters.Properties_.Item("IsPersistent").Value = True
                login_options = connection.Properties_.Item('LoginOptions').Value
                login_options.Properties_.Item('LoginFlags').Value = 2
                login_options.Properties_.Item('MaximumConnections').Value = 1
                parameters.Properties_.Item("LoginOptions").Value = login_options
                parameters.Properties_.Item("IsInformationalSession").Value = False
                parameters.Properties_.Item("InitiatorPortNumber").Value = 0

                for portal_group in connection.Properties_.Item('PortalGroups').Value:
                    for portal in portal_group.Properties_.Item('Portals').Value:
                        if portal.Properties_.Item('Address').Value == ip:
                            parameters.Properties_.Item('TargetPortal').Value = portal
                            print parameters.GetObjectText_()
                            result = connection.ExecMethod_('Login', parameters)
                            print result.Properties_.Item('UniqueSessionId').Value
                            print result.Properties_.Item('UniqueConnectionId').Value
                            return
            raise RuntimeError()

    def login_to_all_availble_targets(self):
        def _uniq(_list):
            '''get a list and return unique list'''
            if len(_list) == 0:
                return []
            uniq_list = [_list[0]]
            for item in _list:
                if item in uniq_list:
                    continue
                else:
                    uniq_list.append(item)
            return uniq_list

        iqns = [ target['iqn'] for target in self.get_sessions()]
        for iqn in _uniq(iqns):
            self.login_to_target(iqn)


    def logout_from_target(self, iqn):
        '''recives an iqn as string and logsout of it
        '''
        from infi.wmi import WmiClient
        client = WmiClient('root\\wmi')
        query = client.execute_query('SELECT * from MSIscsiInitiator_SessionClass')
        for connection in query:
            if iqn == connection.Properties_.Item('TargetName').Value:
                logger.info("logging out of {!r}".format(session_id))
                execute_assert_success('iscsicli', 'LogoutTarget', connection.Properties_.Item('SessionId').Value)

    def logout_from_all_targets(self):
        from infi.wmi import WmiClient
        client = WmiClient('root\\wmi')
        query = client.execute_query('SELECT * from MSIscsiInitiator_SessionClass')
        for connection in query:
            session_id = connection.Properties_.Item('SessionId').Value
            execute_assert_success('iscsicli', 'LogoutTarget', session_id)
            logger.info("logged out of {!r}".format(session_id))



    def get_sessions(self, iqn=None):
        '''returns a list of dicts which contain all active sessions or only iqn specific active session
        '''
        from infi.wmi import WmiClient
        availble_targets = []
        client = WmiClient('root\\wmi')
        for connection in client.execute_query('SELECT * from  MSIscsiInitiator_TargetClass'):
            iqn = connection.Properties_.Item('TargetName').Value
            for portal in connection.Properties_.Item('PortalGroups').Value[0].Properties_.Item('Portals').Value:
                availble_targets.append({'dst_ip':portal.Properties_.Item('Address').Value ,\
                'dst_port': portal.Properties_.Item('Port').Value, 'no_conn': 1, 'iqn': iqn, 'target_obj': connection})
        return availble_targets

    def rescan_all_sessions(self):
        '''rescan all availble sessions
        '''
        raise NotImplementedError()

    def delete_discovered_sessions(self, iqn=None):
        '''delete all discoverd sessions or only iqn specific active sessions
        '''
        for session in self.get_sessions():
            if not iqn:
                execute_assert_success(['iscsicli', 'RemoveTargetPortal', str(session['dst_ip']), str(session['dst_port'])])
            elif iqn == session['iqn']:
                execute_assert_success(['iscsicli', 'RemoveTargetPortal', session['dst_ip'], session['dst_port']])

    def is_iscsi_sw_installed(self):
        '''in windows return True if iSCSI initator sw is running otherwise return False
        '''
        import infi.win32service
        with infi.win32service.ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                return service.is_running()

    def install_iscsi_software_initiator(self):
        '''start the iSCSI service on windows.
           in the future will also autostart the service
        '''
        import infi.win32service
        if not self.is_iscsi_sw_installed():
            logger.debug("trying to start service MSiSCSI")
            with infi.win32service.ServiceControlManagerContext() as scm:
                with scm.open_service('MSiSCSI') as service:
                    try:
                        service.start()
                        logger.debug("service MSiSCSI started")
                    except WinError as e:
                        logger.error("service failed to start {!r}".format(e))

    def _uninstall_iscsi_software_initiator(self):
        import infi.win32service
        if self.is_iscsi_sw_installed():
            logger.debug("shutting down MSiSCSI service")
            with infi.win32service.ServiceControlManagerContext() as scm:
                with scm.open_service('MSiSCSI') as service:
                    try:
                        service.stop()
                        logger.debug("service MSiSCSI stopped")
                    except WinError as e:
                        logger.error("service failed to stop {!r}".format(e))
