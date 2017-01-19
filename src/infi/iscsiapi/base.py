class Session(object):
    '''class that contains the iscsi session information
    '''
    def __init__(self, target, target_endpoint, source_ip, source_iqn, uid, hct):
        # TODO: add hct
        self._target = target
        self._target_endpoint = target_endpoint
        self._source_ip = source_ip
        self._source_iqn = source_iqn
        self._uid = uid
        self._hct = hct

    def __eq__(self, other):
        return isinstance(other, Session) and self._uid == other.get_uid() and self._target_endpoint == other.get_target_endpoint()

    def get_target(self):
        return self._target

    def get_uid(self):
        return self._uid

    def get_target_endpoint(self):
        return self._target_endpoint

    def get_source_ip(self):
        return self._source_ip

    def get_source_iqn(self):
        return self._source_iqn

    def get_hct(self):
        return self._hct


class Target(object):
    '''class that contains the iscsi connection spec
    '''
    def __init__(self, endpoints, discovery_endpoint, iqn):
        self._endpoints = endpoints
        self._discovery_endpoint = discovery_endpoint
        self._iqn = iqn

    def __eq__(self, other):
        return isinstance(other, Target) and self._iqn == other.get_iqn()

    def get_endpoints(self):
        return self._endpoints

    def get_discovery_endpoint(self):
        return self._discovery_endpoint

    def get_iqn(self):
        return self._iqn


class Initiator(object):
    '''class that contains the initiator iscsi details
    '''
    def __init__(self, iqn, initiator_name):
        self._iqn = iqn
        self._initiator_name = initiator_name

    def get_iqn(self):
        return self._iqn

    def get_initiator_name(self):
        return self._initiator_name


class Endpoint(object):
    '''Class that describes the iscsi target endpoint
    '''
    def __init__(self, ip_address, port):
        self._ip_address = ip_address
        self._port = port

    def __eq__(self, other):
        return isinstance(other, Endpoint) and self._ip_address == other.get_ip_address() and self._port == other.get_port()

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
        '''Platform specific function to active the iSCSI feature on an OS
        '''
        raise NotImplementedError()

    def uninstall(self):
        '''Platform specific function to deactivate iSCSI software
        '''
        raise NotImplementedError()


class ConnectionManager(object):
    '''Class that contains the main iscsi methods for connecting iscsi initiator
    to an iscsi target
    '''
    def discover(self, ip_address, port=3260):
        '''perform an iscsi discovery to an ip address
        '''
        raise NotImplementedError()

    def login(self, target, endpoint, auth=None, num_of_connections=1):
        '''receives target and endpoint and login to it
        '''
        raise NotImplementedError()

    def login_all(self, target, auth=None):
        '''login to all endpoints of a target and return the session it achieved
        '''
        raise NotImplementedError()

    def logout(self, session):
        '''receive a session and perform an iSCSI logout
        '''
        raise NotImplementedError()

    def logout_all(self, target):
        '''receive a target and logout of it
        '''
        raise NotImplementedError()

    def get_source_iqn(self):
        raise NotImplementedError()

    def reset_source_iqn(self):
        '''use incase iqn is invalid and regeneration of it is required'''
        raise NotImplementedError()

    def set_source_iqn(self, iqn):
        '''receive an iqn as a string, verify it's valid and set it.
        returns iqn type of the new IQN or None if fails
        '''
        raise NotImplementedError()

    def get_discovered_targets(self):
        '''return a list of discovered target objects
        '''
        raise NotImplementedError()

    def get_sessions(self, target=None):
        '''receive a target or None and return a list of all available sessions
        '''
        raise NotImplementedError()

    def rescan(self):
        '''rescan all available sessions
        '''
        raise NotImplementedError()

    def undiscover(self, target=None):
        '''delete all discovered sessions or only iqn specific active sessions
        '''
        raise NotImplementedError()
