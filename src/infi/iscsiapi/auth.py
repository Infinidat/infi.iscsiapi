class ISCSIAuth(object):
    pass


class NoAuth(ISCSIAuth):
    pass


class ChapAuth(ISCSIAuth):
    def __init__(self, inbound_username, inbound_secret):
        self._inbound_username = inbound_username
        self._inbound_secret = inbound_secret

    def get_inbound_username(self):
        return self._inbound_username

    def get_inbound_secret(self):
        return self._inbound_secret


class MutualChapAuth(ISCSIAuth):
    def __init__(self, inbound_username, inbound_secret, outbound_username, outbound_secret):
        self._inbound_username = inbound_username
        self._inbound_secret = inbound_secret
        self._outbound_username = outbound_username
        self._outbound_secret = outbound_secret

    def get_inbound_username(self):
        return self._inbound_username

    def get_inbound_secret(self):
        return self._inbound_secret

    def get_outbound_username(self):
        return self._outbound_username

    def get_outbound_secret(self):
        return self._outbound_secret
