Overview
========
This package provides a cross-platform API for working with iSCSI storage systems.
Currently supported operating systems are Linux (Ubuntu, Redhat, SUSE) and Windows. Support for Solaris and AIX is underway.

Usage
=====
### Check for host readiness / prepare the host to work with iSCSI
Some operating systems need initial preparation to work with iSCSI. For example, on Windows the iSCSI service must be started
and on Linux there may be packages that must be installed.
The relevant API methods are:
* `is_installed`: Returns whether iSCSI can be used
* `install`: Activate the iSCSI feature or software on an operating system
* `uninstall`: Deactivate iSCSI feature or software

Example:
```python
from infi.iscsiapi import get_iscsi_software_initiator
software_initiator = get_iscsi_software_initiator()
if not software_initiator.is_installed():
    software_initiator.install()
```

### Get or set the source IQN of the software initiator on the host
The operating system generates an IQN address for the software initiator (for example: iqn.1994-05.com.redhat:d6677488767)
The relevant API methods are:
* `get_source_iqn`: get the current source IQN
* `set_source_iqn`: receive an IQN address as a string, verify it's valid and set it

Example:
```python
from infi.iscsiapi import get_iscsiapi
api = get_iscsiapi()
print api.get_source_iqn()
```


### Do discovery and login to a target storage array
To connect to an iSCSI storage array, the host first runs "discovery" on one of the IP addresses of the storage system
to get all the relevant IP addresses. Then for each IP addresses the host runs "login" to get an iSCSI "session".
The relevant API methods are:
* `discover`: perform an iSCSI discovery to an ip address. Returns a `Target` instance.
* `get_discovered_targets`: return a list of discovered target objects
* `undiscover`: delete all discovered sessions or only iqn specific active sessions
* `login`: receives target and endpoint (IP address and port) and login to it
* `login_all`: login to all endpoints of a target and return the session it achieved
* `get_sessions`: list all connected sessions or sessions connected to a specific target.
* `logout`: receive a session and perform an iSCSI logout
* `logout_all`: receive a target and logout of all its sessions

Example:
```python
from infi.iscsiapi import get_iscsiapi
api = get_iscsiapi()
target = api.discover("192.168.1.10")
api.login_all(target)
```


Installation
============
This project is available on PyPI. You can install it by running:

`easy_install infi.iscsiapi`

or

`pip install infi.iscsiapi`

This project uses infi.projector for building the development environment.
For development purposes, clone this repository and run the following commands:

```
easy_install infi.projector
projector devenv build
```

Python 3 support is experimental and not fully tested.
