#!/usr/bin/env python3
# pylint: disable=consider-using-f-string

'''
    This module is used to detect XNU's current SIP status using direct
    kernel calls. This ensures that even if boot.efi strips bits or NVRAM
    is reset, current active SIP status is still detected correctly.

    SIP, or System Integrity Protection, is a security bitmask in XNU
    used to determine OS security features. ex. Filesystem protections, kext loading

    Source originally written by @pudquick:
        https://gist.github.com/pudquick/8b320be960e1654b908b10346272326b

    Adapted by @khronokernel into this module.
'''

from ctypes import CDLL, c_uint, byref
import platform

__version__ = "1.0.4"

SIP_XNU_LIBRARY_NAME = "sip_xnu"


class SipXnu: # pylint: disable=too-many-instance-attributes, too-few-public-methods
    '''
        This class is used to detect XNU's current SIP status
    '''

    class _XnuOsVersion(): # pylint: disable=too-few-public-methods
        OS_CHEETAH = 4
        OS_PUMA = 5
        OS_JAGUAR = 6
        OS_PANTHER = 7
        OS_TIGER = 8
        OS_LEOPARD = 9
        OS_SNOW_LEOPARD = 10
        OS_LION = 11
        OS_MOUNTAIN_LION = 12
        OS_MAVERICKS = 13
        OS_YOSEMITE = 14
        OS_EL_CAPITAN = 15
        OS_SIERRA = 16
        OS_HIGH_SIERRA = 17
        OS_MOJAVE = 18
        OS_CATALINA = 19
        OS_BIG_SUR = 20
        OS_MONTEREY = 21
        OS_VENTURA = 22

    class _XnuSipBitmask(): # pylint: disable=too-few-public-methods
        CSR_ALLOW_UNTRUSTED_KEXTS = 0x1
        CSR_ALLOW_UNRESTRICTED_FS = 0x2
        CSR_ALLOW_TASK_FOR_PID = 0x4
        CSR_ALLOW_KERNEL_DEBUGGER = 0x8
        CSR_ALLOW_APPLE_INTERNAL = 0x10
        CSR_ALLOW_UNRESTRICTED_DTRACE = 0x20
        CSR_ALLOW_UNRESTRICTED_NVRAM = 0x40
        CSR_ALLOW_DEVICE_CONFIGURATION = 0x80
        CSR_ALLOW_ANY_RECOVERY_OS = 0x100
        CSR_ALLOW_UNAPPROVED_KEXTS = 0x200
        CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE = 0x400
        CSR_ALLOW_UNAUTHENTICATED_ROOT = 0x800

    class _XnuSipStatus():  # pylint: disable=too-many-instance-attributes # pylint: disable=too-few-public-methods
        def __init__(
                self,
                csr_dict):
            self.csr_allow_untrusted_kexts = csr_dict["CSR_ALLOW_UNTRUSTED_KEXTS"]
            self.csr_allow_unrestricted_fs = csr_dict["CSR_ALLOW_UNRESTRICTED_FS"]
            self.csr_allow_task_for_pid = csr_dict["CSR_ALLOW_TASK_FOR_PID"]
            self.csr_allow_kernel_debugger = csr_dict["CSR_ALLOW_KERNEL_DEBUGGER"]
            self.csr_allow_apple_internal = csr_dict["CSR_ALLOW_APPLE_INTERNAL"]
            self.csr_allow_unrestricted_dtrace = csr_dict["CSR_ALLOW_UNRESTRICTED_DTRACE"]
            self.csr_allow_unrestricted_nvram = csr_dict["CSR_ALLOW_UNRESTRICTED_NVRAM"]
            self.csr_allow_device_configuration = csr_dict["CSR_ALLOW_DEVICE_CONFIGURATION"]
            self.csr_allow_any_recovery_os = csr_dict["CSR_ALLOW_ANY_RECOVERY_OS"]
            self.csr_allow_unapproved_kexts = csr_dict["CSR_ALLOW_UNAPPROVED_KEXTS"]
            self.csr_allow_executable_policy_override = csr_dict[
                "CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE"]
            self.csr_allow_unauthenticated_root = csr_dict["CSR_ALLOW_UNAUTHENTICATED_ROOT"]

    class _SipStatus: # pylint: disable=too-many-instance-attributes # pylint: disable=too-few-public-methods
        def __init__(  # pylint: disable=too-many-arguments
                self,
                value,
                breakdown,
                can_edit_root,
                can_write_nvram,
                can_load_arbitrary_kexts):
            self.value = value
            self.breakdown = breakdown
            self.can_edit_root = can_edit_root
            self.can_write_nvram = can_write_nvram
            self.can_load_arbitrary_kexts = can_load_arbitrary_kexts

    def __init__(self, debug=False):
        self.xnu_major = 0
        self.xnu_minor = 0
        self.xnu_patch = 0
        self.sip_status = 0

        self.debug = debug

        self.lib_system_path = "/usr/lib/libSystem.dylib"

        self.sip_dict = {
            "CSR_ALLOW_UNTRUSTED_KEXTS": 0,
            "CSR_ALLOW_UNRESTRICTED_FS": 0,
            "CSR_ALLOW_TASK_FOR_PID": 0,
            "CSR_ALLOW_KERNEL_DEBUGGER": 0,
            "CSR_ALLOW_APPLE_INTERNAL": 0,
            "CSR_ALLOW_UNRESTRICTED_DTRACE": 0,
            "CSR_ALLOW_UNRESTRICTED_NVRAM": 0,
            "CSR_ALLOW_DEVICE_CONFIGURATION": 0,
            "CSR_ALLOW_ANY_RECOVERY_OS": 0,
            "CSR_ALLOW_UNAPPROVED_KEXTS": 0,
            "CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE": 0,
            "CSR_ALLOW_UNAUTHENTICATED_ROOT": 0
        }

        self.__is_darwin()
        self.__detect_xnu_version()

        self.sip_status = self.__detect_sip_status()

        self.__update_sip_dict()

        self.sip_object = self._SipStatus(
            value=self.sip_status,
            breakdown=self._XnuSipStatus(self.sip_dict),
            can_edit_root=self.__sip_can_edit_root(),
            can_write_nvram=self.__sip_can_write_nvram(),
            can_load_arbitrary_kexts=self.__sip_can_load_arbitrary_kexts()
        )

    def get_sip_status(self):
        '''
        Returns the current SIP status

        Returns:
            dict: Current SIP status
        '''

        self.__debug_printing("Returning SIP status:")
        self.__debug_printing("   Value: %s" % self.sip_object.value)
        self.__debug_printing("   Breakdown:")
        for key, value in self.sip_object.breakdown.__dict__.items():
            self.__debug_printing("      %s: %s" % (key, value))
        self.__debug_printing(
            "   Can edit root: %s" %
            self.sip_object.can_edit_root)
        self.__debug_printing(
            "   Can write NVRAM: %s" %
            self.sip_object.can_write_nvram)
        self.__debug_printing(
            "   Can load arbitrary kexts: %s" %
            self.sip_object.can_load_arbitrary_kexts)

        return self.sip_object

    def __debug_printing(self, message):
        '''
        Prints the message if the debug flag is set

        Args:
            message (str): Message to be printed

        Format:
            [SIP_XNU_LIBRARY_NAME][TIME] MESSAGE
        '''

        if self.debug:
            print(
                "[%s] %s" %
                (SIP_XNU_LIBRARY_NAME,
                 message))

    def __debug_exception(self, message):
        raise Exception(
            "[%s] %s" %
            (SIP_XNU_LIBRARY_NAME, message))

    def __is_darwin(self):
        '''
        Checks if the current system is Darwin
        '''

        if platform.system() != "Darwin":
            self.__debug_exception("Not Darwin")

    def __detect_xnu_version(self):
        '''
        Detects the XNU version of the current system
        '''

        xnu_version = platform.release()
        xnu_version = xnu_version.split(".")

        self.xnu_major = int(xnu_version[0])
        self.xnu_minor = int(xnu_version[1])
        self.xnu_patch = int(xnu_version[2])

        self.__debug_printing("XNU version: %d.%d.%d" %
                              (self.xnu_major, self.xnu_minor, self.xnu_patch))

    def __detect_sip_status(self):
        '''
        Detects the SIP status of the current system

        Returns:
            int: csr_active_config value

        Notes:
            If OS detected is older than 10.11, returns max int value
        '''

        if self.xnu_major < self._XnuOsVersion.OS_EL_CAPITAN:
            # Assume unrestricted
            return 65535

        libsys = CDLL(self.lib_system_path)
        result = c_uint(0)
        error = libsys.csr_get_active_config(byref(result))

        if error != 0:
            self.__debug_exception(
                "Error while detecting SIP status: %d" %
                error)

        self.__debug_printing("csr_active_config: %d" % result.value)

        return result.value

    def __sip_can_edit_root(self):
        '''
        Checks if SIP allows root filesystem to be edited

        Returns:
            bool: True if SIP allows root filesystem to be edited
        '''

        if self.sip_status & self._XnuSipBitmask.CSR_ALLOW_UNRESTRICTED_FS:
            if self.xnu_major < self._XnuOsVersion.OS_BIG_SUR:
                return True

            if self.sip_status & self._XnuSipBitmask.CSR_ALLOW_UNAUTHENTICATED_ROOT:
                return True

        return False

    def __sip_can_load_arbitrary_kexts(self):
        '''
        Checks if SIP allows arbitrary kexts to be loaded

        Returns:
            bool: True if SIP allows arbitrary kexts to be loaded
        '''

        if self.sip_status & self._XnuSipBitmask.CSR_ALLOW_UNTRUSTED_KEXTS:
            return True

        return False

    def __sip_can_write_nvram(self):
        '''
        Checks if SIP allows NVRAM to be written

        Returns:
            bool: True if SIP allows NVRAM to be written
        '''

        if self.sip_status & self._XnuSipBitmask.CSR_ALLOW_UNRESTRICTED_NVRAM:
            return True

        return False

    def __update_sip_dict(self):
        '''
        Updates SIP_DICT with new SIP status
        '''

        for key, value in self.sip_dict.items(): # pylint: disable=unused-variable
            for sip_key, sip_value in self._XnuSipBitmask.__dict__.items():
                if sip_key == key:
                    if self.sip_status & sip_value:
                        self.sip_dict[key] = True
                    else:
                        self.sip_dict[key] = False


if __name__ == "__main__":
    SipXnu(debug=True).get_sip_status()
