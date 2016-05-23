
from infi.dtypes.iqn import IQN
#from infi.dtypes.hctl import HCT


class Session(object):
    '''class that contains the iscsi session information
    '''
    def __init__(self, target_endpoint, source_ip, source_iqn, uid):
        # self._number_of_connections = number_of_connections
        #self._hct = hct
        self._target_endpoint = target_endpoint
        self._source_ip = source_ip
        self._source_iqn = source_iqn
        self._uid = uid

    # def get_number_of_connections(self):
        # return self._number_of_connections

    def get_hct(self):
        return self._hct

    def get_uid(self):
        return self._uid

    def get_target_endpoint(self):
        return self._target_endpoint

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

    def __eq__(self, other):
        return self._iqn == other.get_iqn()

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


class SoftwareInitiator(object):
    def is_installed(self):
        '''Platform specific function to understand if iSCSI can be used now
        '''
        raise NotImplementedError()

    def install(self):
        '''Platfrom specific function to active the iSCSI feature on an OS
        '''
        raise NotImplementedError()

    def uninstall(self):
        '''Plarform specific function to deactivate iSCSI software
        '''
        raise NotImplementedError()


class ConnectionManager(object):
    '''Class that contain the main iscsi methods for connecting iscsi initiator
    to an iscsi target
    '''
    def discover(self, ip_address, port=3260, outband_chap=None, inbound_chap=None):
        '''perform an iscsi discovery to an ip address
        '''
        raise NotImplementedError()

    def login(self, target, endpoint, num_of_connections=1):
        '''recives target and endpoing and login to it
        '''
        raise NotImplementedError()

    def login_all(self, target):
        ''' login to all endpoin of a target and return the session it achived
        '''
        raise NotImplementedError()

    def logout(self, session):
        '''recive a session and perform an iSCSI logout
        '''
        raise NotImplementedError()

    def logout_all(self, target):
        '''recive a target and logout of it
        '''
        raise NotImplementedError()

    def get_source_iqn(self):
        raise NotImplementedError()

    def set_source_iqn(self, iqn):
        '''recive an iqn as a string, verify it's valid and set it.
        returns iqn type of the new IQN or None if fails
        '''
        raise NotImplementedError()

    def get_discovered_targets(self):
        '''return a list of dicvoered target objects
        '''
        raise NotImplementedError()

    def get_sessions(self, target=None):
        '''recive a target or None and return a list of all available sessions
        '''
        raise NotImplementedError()

    def rescan(self):
        '''rescan all availble sessions
        '''
        raise NotImplementedError()

    def undiscover(self, target=None):
        '''delete all discoverd sessions or only iqn specific active sessions
        '''
        raise NotImplementedError()
