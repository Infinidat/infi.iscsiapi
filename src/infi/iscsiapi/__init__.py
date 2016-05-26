import os


def get_iscsiapi():
    if os.name == 'nt':
        from . import windows
        return windows.WindowsISCSIapi()
    elif os.name == 'posix':
        from . import linux
        return linux.LinuxISCSIapi()

def get_iscsi_software_initator():
    if os.name == 'nt':
        from . import windows
        return windows.MicrosoftSoftwareInitiator()
    elif os.name == 'posix':
        from . import linux
        return linux.LinuxSoftwareInitiator()
