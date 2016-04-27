

class ISCSIapi(object):

    def discover_target(self, ip_adder):
        '''initiate discovery and returns a list of dicts which contain all availble targets
        '''
        raise NotImplementedError()

    def login_to_target(self, iqn):
        '''recives an iqn as string and login to it
        '''
        raise NotImplementedError()

    def login_to_all_availble_targets(self):
        raise NotImplementedError()

    def logout_from_target(self, iqn):
        '''recives an iqn as string and logsout of it
        '''
        raise NotImplementedError()

    def logout_from_all_targets(self):
        raise NotImplementedError()

    def get_sessions(self, iqn=None):
        '''returns a list of dicts which contain all active sessions or only iqn specific active session
        '''
        raise NotImplementedError()

    def rescan_all_sessions(self):
        '''rescan all availble sessions
        '''
        raise NotImplementedError()

    def delete_discovered_sessions(self, iqn=None):
        '''deletea all discoverd sessions or only iqn specific active sessions
        '''
        raise NotImplementedError()

    def is_iscsi_sw_installed(self):
        ''' return True if iSCSI initator sw is installed otherwise return False
        '''
        raise NotImplementedError()

    def install_iscsi_software_initiator(self):
        raise NotImplementedError()
