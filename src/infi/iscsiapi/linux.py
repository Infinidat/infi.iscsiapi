from infi.execute import execute_assert_success, execute, ExecutionError

from logging import getLogger
logger = getLogger(__name__)

ISCSI_FS_PATH = '/var/lib/iscsi/nodes/'

class linuxISCSIapi(iSCSIapi):
    def discover_target(ip_addr):
    '''initiate discovery and returns a list of dicts which contain all availble targets
    '''
    execute_assert_success(['iscsiadm', '-m', 'discovery', '-t', 'st', '-p', ip_addr])

    def login_to_target(iqn, ip=None):
    '''recives an iqn as string and login to it with ip tries to connect to the target ip
    '''
    if not ip:
        execute_assert_success(['iscsiadm', '-m', 'node', '-l', '-T', target_iqn])
    else:
        execute_assert_success(['iscsiadm', '-m', 'node', '-l', '-T', target_iqn, '-p', ip])


    def login_to_all_availble_targets():
        execute_assert_success(['iscsiadm', '-m', 'node', '-l'])

    def logout_from_target(iqn):
    '''recives an iqn as string and logsout of it
    '''
        execute((['iscsiadm', '-m', 'node', '-u', '-T', iqn]))

    def logout_from_all_targets():
        execute((['iscsiadm', '-m', 'node', '-u']))

    def get_sessions(iqn=None):
        '''returns a list of dicts which contain all active sessions or only iqn specific active session
        '''
        import os
        if not os.path.isdir(ISCSI_FS_PATH):
            logger.error("storage isn't discoverabled from this host when it should be")
            return
        return os.listdir(ISCSI_FS_PATH)

    def rescan_all_sessions():
        '''rescan all availble sessions
        '''
        execute(['iscsiadm', '-m', 'session', '--rescan'])

    def delete_discovered_sessions(iqn=None, ip=None):
        '''with no arguments delete all discoverd sessions
        with ip or iqn delete a specific ip session or all sessions to a specific iqn
        '''
        if not iqn and not ip:
            execute(['iscsiadm', '-m', 'node', '-o', 'delete'])
        elif iqn and not ip:
            execute(['iscsiadm', '-m', 'node', '-o', 'delete', iqn])
        elif ip and not iqn:
            execute(['iscsiadm', '-m', 'node', '-o', 'delete', '-p', ip])
        else:
            raise AttributeError("function can't recive both ip and iqn.")


    def is_iscsi_sw_installed():
        ''' return True if iSCSI initator sw is installed otherwise return False
        '''
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            logger.debug("checking if iSCSI sw is installed")
            process = execute(['rpm', '-q', '--quiet', 'iscsi-initiator-utils'])
        if process.get_returncode() != 0:
            logger.debug("iscsi sw isn't installed")
            return False
        else:
            logger.debug("iscsi sw installed")
            return True

    def install_iscsi_software_initiator():
        from infi.os_info import get_platform_string
        if 'centos' in get_platform_string() or 'redhat' in get_platform_string():
            execute_assert_success(['yum', 'install', '-y', 'iscsi-initiator-utils'])
