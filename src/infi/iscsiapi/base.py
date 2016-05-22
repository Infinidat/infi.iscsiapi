
from infi.dtypes.iqn import IQN
#from infi.dtypes.hctl import HCT


class Session(object):
    '''class that contains the iscsi session information
    '''
    def __init__(self, target, source_ip, source_iqn, uid):
        # self._number_of_connections = number_of_connections
        #self._hct = hct
        self._target = target
        self._source_ip = source_ip
        self._source_iqn = source_iqn
        self._uid = uid


    # def get_number_of_connections(self):
        # return self._number_of_connections

    def get_hct(self):
        return self._hct

    def get_uid(self):
        self._uid

    def get_target(self):
        return self._target

    def get_source_ip(self):
        return self._source_ip

    def get_source_iqn(self):
        return self._source_iqn


class Endpoint(object):
    ''' class that discribes an IP endpoint
    '''
    def __init__(self, ip_address, port):
        self._ip_address = ip_address
        self._port = port

    def get_ip_address(self):
        return self._ip_address

    def get_port(self):
        return self.get_port


class Target(object):
    '''class that contains the iscsi connection spec
    '''
    def __init__(self, endpoints, inbound_chap, outband_chap, discovery_endpoint, iqn):
        self._endpoints = endpoints
        self._inbound_chap = inbound_chap
        self._outband_chap = outband_chap
        self._discovery_endpoint = discovery_endpoint
        self._iqn = iqn

    def get_endpoints(self):
        return self._endpoints

    def get_inbound_chap(self):
        return self._inbound_chap

    def get_outbound_chap(self):
        return self._outband_chap

    def get_discovery_endpoint(self):
        return self._discovery_endpoint

    def get_iqn(self):
        return self._iqn

class Initiator(object):
    '''class that contain the initiator iscsi details
    '''
    def __init__(self, iqn, initiator_name):
        self._iqn = iqn
        self._initiator_name = initiator_name

    def get_iqn(self):
        return self._iqn

    def get_initiator_name(self):
        return self._initiator_name


class Endpoint(object):
    '''Class that discribes the iscsi target endpoint
    '''
    def __init__(self, ip_address, port):
        self._ip_address = ip_address
        self._port = port

    def get_ip_address(self):
        return self._ip_address

    def get_port(self):
        return self._port


class ConnectionManager(object):
    '''Class that contain the main iscsi methods for connecting iscsi initiator
    to an iscsi target
    '''
    def discover(ip_address, port=3260, outband_chap=None, inbound_chap=None):
        '''perform an iscsi discovery to an ip address
        '''
        raise NotImplementedError()

    def get_source_iqn(self):
        raise NotImplementedError()

class ISCSIapi(object):
    '''Class that contain the main iscsi methods for connecting iscsi initiator
    to an iscsi target
    '''

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
