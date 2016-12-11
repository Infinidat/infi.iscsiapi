from infi.execute import execute_assert_success

def get_platform_specific_iscsi_service():
    from infi.os_info import get_platform_string
    platform = get_platform_string()
    if platform.startswith('windows'):
        return ISCSIWindowsServiceStates()
    elif platform.startswith('linux'):
        return ISCSILinuxServiceStates()
    elif platform.startswith('solaris'):
        return ISCSISolarisServiceStates()
    else:
        raise ImportError("not supported on this platform")

class ISCSIServiceStates(object):
    def start(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

class ISCSILinuxServiceStates(ISCSIServiceStates):
    def stop(self):
        execute_assert_success(['iscsiadm', '-m', 'node', '-u'])

    def start(self):
        execute_assert_success(['iscsiadm', '-m', 'node', '-l'])


class ISCSIWindowsServiceStates(ISCSIServiceStates):
    def stop(self):
        from infi.win32service import ServiceControlManagerContext
        with ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                service.safe_stop()
                service.wait_on_pending()

    def start(self):
        from infi.win32service import ServiceControlManagerContext
        with ServiceControlManagerContext() as scm:
            with scm.open_service('MSiSCSI') as service:
                service.safe_start()
                service.wait_on_pending()

class ISCSISolarisServiceStates(ISCSIServiceStates):
    def start(self):
        from infi.iscsiapi import get_iscsiapi
        api = get_iscsiapi()
        api._enable_iscsi_auto_login()

    def stop(self):
        from infi.iscsiapi import get_iscsiapi
        api = get_iscsiapi()
        api._disable_iscsi_auto_login()
