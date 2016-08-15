__iscsiapi = None
__iscsi_software_initiator = None


def get_iscsiapi():
    global __iscsiapi
    if __iscsiapi is None:
        __iscsiapi = _get_platform_specific_iscsiapi()
    return __iscsiapi


def get_iscsi_software_initiator():
    global __iscsi_software_initiator
    if __iscsi_software_initiator is None:
        __iscsi_software_initiator = _get_platform_specific_iscsi_software_initiator()
    return __iscsi_software_initiator


def _get_platform_specific_iscsiapi():
    from infi.os_info import get_platform_string
    platform = get_platform_string()
    if platform.startswith('windows'):
        from . import windows
        return windows.WindowsISCSIapi()
    elif platform.startswith('linux'):
        from . import linux
        return linux.LinuxISCSIapi()
    elif platform.startswith('solaris'):
        from . import solaris
        return solaris.SolarisISCSIapi()
    else:
        raise ImportError("not supported on this platform")


def _get_platform_specific_iscsi_software_initiator():
    from infi.os_info import get_platform_string
    platform = get_platform_string()
    if platform.startswith('windows'):
        from . import windows
        return windows.MicrosoftSoftwareInitiator()
    elif platform.startswith('linux'):
        from . import linux
        return linux.LinuxSoftwareInitiator()
    elif platform.startswith('solaris'):
        from . import solaris
        return solaris.SolarisSoftwareInitiator()
    else:
        raise ImportError("not supported on this platform")
