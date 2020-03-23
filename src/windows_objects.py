import ctypes
import win32security
import win32api
from enum import Enum

#---------------------------------------------------#
# Name:     Windows Objects Class                   #
# Purpose:  Contains permission bitmasks / sets     #
# Author:   @jfaust0                                #
# Website:  sevrosecurity.com                       #
#---------------------------------------------------#
  
class windows_security_enums(Enum):
  FullControl               =   ctypes.c_uint32(0x1f01ff)
  modify                    =   ctypes.c_uint32(0x0301bf)
  ReadExecAndSynchronize    =   ctypes.c_uint32(0x1200a9)
  Synchronize               =   ctypes.c_uint32(0x100000)
  ReadAndExecute            =   ctypes.c_uint32(0x0200a9)
  ReadAndWrite              =   ctypes.c_uint32(0x02019f)
  Read                      =   ctypes.c_uint32(0x020089)
  Write                     =   ctypes.c_uint32(0x000116)

# Windows NT Permission Bitmasks
class nt_security_enums(Enum):
  GenericRead               =   ctypes.c_uint32(0x80000000)
  GenericWrite              =   ctypes.c_uint32(0x40000000)
  GenericExecute            =   ctypes.c_uint32(0x20000000)
  GenericAll                =   ctypes.c_uint32(0x10000000)
  MaximumAllowed            =   ctypes.c_uint32(0x02000000)
  AccessSystemSecurity      =   ctypes.c_uint32(0x01000000)
  Synchronize               =   ctypes.c_uint32(0x00100000)
  WriteOwner                =   ctypes.c_uint32(0x00080000)
  WriteDAC                  =   ctypes.c_uint32(0x00040000)
  ReadControl               =   ctypes.c_uint32(0x00020000)
  Delete                    =   ctypes.c_uint32(0x00010000)
  WriteAttributes           =   ctypes.c_uint32(0x00000100)
  ReadAttributes            =   ctypes.c_uint32(0x00000080)
  DeleteChild               =   ctypes.c_uint32(0x00000040)
  ExecuteTraverse           =   ctypes.c_uint32(0x00000020)
  WriteExtendedAttributes   =   ctypes.c_uint32(0x00000010)
  ReadExtendedAttributes    =   ctypes.c_uint32(0x00000008)
  AppendDataAddSubdirectory =   ctypes.c_uint32(0x00000004)
  WriteDataAddFile          =   ctypes.c_uint32(0x00000002)
  ReadDataListDirectory     =   ctypes.c_uint32(0x00000001)
  
# When enumerating C:\Windows objects, this class mitigates BS redirects. 
class disable_file_system_redirection:
    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))
    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)


class SDDL():
#https://itconnect.uw.edu/wares/msinf/other-help/understanding-sddl-syntax/
  """
      Access Mask: 32-bits
      ___________________________________
      | Bit(s)  | Meaning                 |
      -----------------------------------
      | 0 - 15  | Object Access Rights    |
      | 16 - 22 | Standard Access Rights  |
      | 23      | Can access security ACL |
      | 24 - 27 | Reserved                |
      | 28 - 31 | Generic Access Rights   |
      -----------------------------------
  """

  SDDL_TYPE = {
          'O': 'Owner',
          'G': 'Group',
          'D': 'DACL',
          'S': 'SACL'
            }

  ACCESS = {
            # ACE Types
            'A' : 'ACCESS_ALLOWED',
            'D' : 'ACCESS_DENIED',
            'OA': 'ACCESS_ALLOWED_OBJECT',
            'OD': 'ACCESS_DENIED_OBJECT',
            'AU': 'SYSTEM_AUDIT',
            'AL': 'SYSTEM_ALARM',
            'OU': 'SYSTEM_AUDIT_OBJECT',
            'OL': 'SYSTEM_ALARM_OBJECT',

            # ACE Flags
            'CI': 'CONTAINER_INHERIT',
            'OI': 'OBJECT_INHERIT',
            'NP': 'NO_PROPAGATE_INHERIT',
            'IO': 'INHERIT_ONLY',
            'ID': 'INHERITED',
            'SA': 'SUCCESSFUL_ACCESS',
            'FA': 'FAILED_ACCESS',

            # Generic Access Rights
            'GA': 'GENERIC_ALL',
            'GR': 'GENERIC_READ',
            'GW': 'GENERIC_WRITE',
            'GX': 'GENERIC_EXECUTE',

            # Standard Access Rights
            'RC': 'READ_CONTROL',
            'SD': 'DELETE',
            'WD': 'WRITE_DAC',
            'WO': 'WRITE_OWNER',

            # Directory Service Object Access Rights
            'RP': 'DS_READ_PROP',
            'WP': 'DS_WRITE_PROP',
            'CC': 'DS_CREATE_CHILD',
            'DC': 'DS_DELETE_CHILD',
            'CR': 'SDDL_CONTROL_ACCESS',
            'LC': 'DS_LIST',
            'SW': 'DS_SELF',
            'LO': 'DS_LIST_OBJECT',
            'DT': 'DS_DELETE_TREE',

            # File Access Rights
            'FA': 'FILE_ALL_ACCESS',
            'FR': 'FILE_GENERIC_READ',
            'FW': 'FILE_GENERIC_WRITE',
            'FX': 'FILE_GENERIC_EXECUTE',

            # Registry Access Rights
            'KA': 'KEY_ALL_ACCESS',
            'KR': 'KEY_READ',
            'KW': 'KEY_WRITE',
            'KE': 'KEY_EXECUTE'}

  ACCESS_HEX = {
            # Generic Access Rights
            0x10000000: 'GA',
            0x20000000: 'GX',
            0x40000000: 'GW',
            0x80000000: 'GR',

            # Standard Access Rights
            0x00010000: 'SD',
            0x00020000: 'RC',
            0x00040000: 'WD',
            0x00080000: 'WO',

            # Object Access Rights
            0x00000001: 'CC',
            0x00000002: 'DC',
            0x00000004: 'LC',
            0x00000008: 'SW',
            0x00000010: 'RP',
            0x00000020: 'WP',
            0x00000040: 'DT',
            0x00000080: 'LO',
            0x00000100: 'CR'
            }

  TRUSTEE = {
            'AO': 'Account Operators',
            'AC': 'All Application Packages',
            'RU': 'Pre-Win2k Compatibility Access',
            'AN': 'Anonymous',
            'AU': 'Authenticated Users',
            'BA': 'Administrators',
            'BG': 'Guests',
            'BO': 'Backup Operators',
            'BU': 'Users',
            'CA': 'Certificate Publishers',
            'CD': 'Certificate Services DCOM Access',
            'CG': 'Creator Group',
            'CO': 'Creator Owner',
            'DA': 'Domain Admins',
            'DC': 'Domain Computers',
            'DD': 'Domain Controllers',
            'DG': 'Domain Guests',
            'DU': 'Domain Users',
            'EA': 'Enterprise Admins',
            'ED': 'Enterprise Domain Controllers',
            'RO': 'Enterprise Read-Only Domain Controllers',
            'WD': 'Everyone',
            'PA': 'Group Policy Admins',
            'IU': 'Interactive Users',
            'LA': 'Local Administrator',
            'LG': 'Local Guest',
            'LS': 'Local Service',
            'SY': 'NT AUTHORITY/System',
            'NU': 'Network',
            'LW': 'Low Integrity',
            'ME': 'Medium Integrity',
            'OW': 'NT SERVICE/Dhcp',
            'HI': 'High Integrity',
            'SI': 'System Integrity',
            'NO': 'Network Configuration Operators',
            'NS': 'Network Service',
            'PO': 'Printer Operators',
            'PS': 'Self',
            'PU': 'Power Users',
            'RS': 'RAS Servers',
            'RD': 'Remote Desktop Users',
            'RE': 'Replicator',
            'RC': 'Restricted Code',
            'SA': 'Schema Administrators',
            'SO': 'Server Operators',
            'SU': 'Service'
           }

