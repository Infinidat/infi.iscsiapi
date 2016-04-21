__import__("pkg_resources").declare_namespace(__name__)

__storage_model = None

from logging import getLogger
from infi.exceptools import chain
logger = getLogger(__name__)

def get_platform_name():
    from infi.os_info import get_platform_string
    return get_platform_string().split('-')[0]

def _get_platform_specific_iscsi_class():
    # do platform-specific magic here.
    # Copy paste from Storagemodule
    from .base import StorageModel as PlatformStorageModel  # helps IDEs
    from brownie.importing import import_string
    plat = get_platform_name()
    platform_module_string = "{}.{}".format(__name__, plat)
    platform_module = import_string(platform_module_string)
    try:
        PlatformStorageModel = getattr(platform_module, "{}StorageModel".format(plat.capitalize()))
    except AttributeError:
        msg = "Failed to import platform-specific storage model"
        logger.exception(msg)
        raise chain(ImportError(msg))
    return PlatformStorageModel

def _get_platform_specific_storagemodel():
    return _get_platform_specific_storagemodel_class()()

def get_storage_model():
    """returns a global instance of a `infi.storagemodel.base.StorageModel`. """
    # pylint: disable=W0603,C0103
    global __storage_model
    if __storage_model is None:
        __storage_model = _get_platform_specific_storagemodel()
    return __storage_model
