import os
import re
import io
import sys
import time
import numpy
import ctypes
import getpass
import win32api
import threading
import linecache
import win32security
import win32con as con
from colorama import Fore, init
from enum import Enum
from . import windows_objects
init()
sys.setrecursionlimit(10000)

class permissions:

    def __init__(self, o_dir):
        self.name = "Permission Analysis"
        self.error_index = 0
        self.re_valid_string = re.compile(r"^[ADO][ADLU]?\:\(.*\)$")
        self.re_perms = re.compile(r"\(([^\(\)]+)\)")
        self.re_type = re.compile(r"^[DOGS]")
        self.re_owner = re.compile(r"^O:[^:()]+(?=[DGS]:)")
        self.re_group = re.compile(r"G:[^:()]+(?=[DOS]:)")
        self.re_acl = re.compile(r"[DS]:.+$")
        self.re_const = re.compile(r"(\w\w)")
        self.re_non_acl = re.compile(r"[^:()]+$")
        self.SDDL_OBJECT = windows_objects.SDDL()
        self.ACCESS = self.SDDL_OBJECT.ACCESS
        self.SDDL_TYPE = self.SDDL_OBJECT.SDDL_TYPE
        self.TRUSTEE = self.SDDL_OBJECT.TRUSTEE
        self.ACCESS_HEX = self.SDDL_OBJECT.ACCESS_HEX
        self.__username = str(getpass.getuser()).lower()
        self.__output_dir = o_dir
        self.__mutex = threading.Lock()
        self.__error_out_file = open(f"{self.__output_dir}/errors.txt", "w+")
        self.__CONVENTIONAL_ACES = {
            win32security.ACCESS_ALLOWED_ACE_TYPE: "ALLOW",
            win32security.ACCESS_DENIED_ACE_TYPE: "DENY",
        }


    # ==========================================================#
    # Purpose:  Obtains ACL values for a single Registry path / #
    #           key. This function is exclusive to the procmon  #
    # Return:   dictionary                                      #
    # ==========================================================#
    def get_registry_key_acl_procmon(self, path_dict):
        try:
            '''
            cmd = {
                "proc_name" : proc_name, 
                "orig_cmd"  : orig_cmd, 
                "clean_cmd" : clean_cmd,
                "operation" : operation,
                "integrity" : integrity
                }
            '''
            registry_dict = dict(path_dict)                 # A dictionary object containing all information regarding a single key
            r_path = registry_dict["clean_cmd"]             # The cleaned registry key path - ready for DACL enumeration

            # HKLM support
            if "hklm" in r_path:
                try:
                    path = r_path.split(":\\")[1]
                except:
                    path = r_path.split("hklm\\")[1]
                key = win32api.RegOpenKey(
                    con.HKEY_LOCAL_MACHINE,
                    path,
                    0,
                    con.KEY_ENUMERATE_SUB_KEYS 
                    | con.KEY_QUERY_VALUE 
                    | con.KEY_READ,
                )

            # HKCU Support
            if "hkcu" in r_path:
                try:
                    path = r_path.split(":\\")[1]
                except:
                    path = r_path.split("hkcu\\")[1]
                key = win32api.RegOpenKey(
                    con.HKEY_CURRENT_USER,
                    path,
                    0,
                    con.KEY_ENUMERATE_SUB_KEYS 
                    | con.KEY_QUERY_VALUE 
                    | con.KEY_READ,
                )

            # HKCR Support
            if "hkcr" in r_path:
                try:
                    path = r_path.split(":\\")[1]
                except:
                    path = r_path.split("hkcr\\")[1]
                key = win32api.RegOpenKey(
                    con.HKEY_CLASSES_ROOT,
                    path,
                    0,
                    con.KEY_ENUMERATE_SUB_KEYS 
                    | con.KEY_QUERY_VALUE 
                    | con.KEY_READ,
                )


            sd = win32api.RegGetKeySecurity(            # Obtain a Registry Security Object
                key,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.OWNER_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()       # Registry Security DACL
            owner_sid = sd.GetSecurityDescriptorOwner() # Registry Security Owner
            sddl_string = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                sd,
                win32security.SDDL_REVISION_1,
                win32security.DACL_SECURITY_INFORMATION)   # Gives us an SDDL String we can now parse. 

            all_permissions = dict(self.__sddl_dacl_parse(sddl_string))
            keys = all_permissions.keys()
            acls = ""

            # Enumerate all the keys (registry paths) and ACLS
            for key in keys:
                acls += f"{key}: {all_permissions[key]}\n"
            
            acl_dict = {
                "process_name": path_dict["proc_name"],
                "integrity": path_dict["integrity"],
                "operation": path_dict["operation"],
                "original_cmd": path_dict["orig_cmd"],
                "path": r_path,
                "acls": acls
                }
            return acl_dict

        except Exception as e:
            error = str(e).lower()
            if (
                "find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
            ):
                final_dict = {
                    "key_path":r_path,
                    "acls": "ERROR",
                    "error": error
                    }
                return final_dict

            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""
                final_dict = {
                    "key_path":r_path,
                    "acls": note,
                    "error": error
                    }
                return final_dict

            else:
                self.__write_error(r_path + "\n" + all_permissions)
                self.__print_exception()
                exit(0)


    # ==========================================================#
    # Purpose:  Obtains ACL values for a single Registry path   # 
    #           / key                                           #
    # Return:   Dictionary                                      #
    # ==========================================================#
    def get_registry_key_acl(self, root_key):
        try:

            r_path = root_key.lower()
            all_permissions = ""

            # HKLM support
            if "hklm" in r_path:
                try:
                    path = r_path.split(":\\")[1]
                except:
                    path = r_path.split("hklm\\")[1]
                key = win32api.RegOpenKey(
                    con.HKEY_LOCAL_MACHINE,
                    path,
                    0,
                    con.KEY_ENUMERATE_SUB_KEYS 
                    | con.KEY_QUERY_VALUE 
                    | con.KEY_READ,
                )

            # HKCU Support
            if "hkcu" in r_path:
                try:
                    path = r_path.split(":\\")[1]
                except:
                    path = r_path.split("hkcu\\")[1]
                key = win32api.RegOpenKey(
                    con.HKEY_CURRENT_USER,
                    path,
                    0,
                    con.KEY_ENUMERATE_SUB_KEYS 
                    | con.KEY_QUERY_VALUE 
                    | con.KEY_READ,
                )

            # HKCR Support
            if "hkcr" in r_path:
                try:
                    path = r_path.split(":\\")[1]
                except:
                    path = r_path.split("hkcr\\")[1]
                key = win32api.RegOpenKey(
                    con.HKEY_CLASSES_ROOT,
                    path,
                    0,
                    con.KEY_ENUMERATE_SUB_KEYS 
                    | con.KEY_QUERY_VALUE 
                    | con.KEY_READ,
                )

            sd = win32api.RegGetKeySecurity(
                key,
                win32security.DACL_SECURITY_INFORMATION
                | win32security.OWNER_SECURITY_INFORMATION,
            )
            dacl = sd.GetSecurityDescriptorDacl()
            owner_sid = sd.GetSecurityDescriptorOwner()
            sddl_string = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
                sd,
                win32security.SDDL_REVISION_1,
                win32security.DACL_SECURITY_INFORMATION,
            )

            all_permissions = dict(self.__sddl_dacl_parse(sddl_string))
            keys = all_permissions.keys()
            acls = ""

            for key in keys:
                acls += f"{key}: {all_permissions[key]}\n"
       
            final_dict = {
                "key_path":r_path,
                "acls": acls,
                "error": None
                }

            return final_dict

        except Exception as e:
            error = str(e).lower()
            if (
                "find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
            ):
                       
                final_dict = {
                    "key_path":r_path,
                    "acls": None,
                    "error": error
                    }
                return final_dict

            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""
                final_dict = {
                    "key_path":r_path,
                    "acls": note,
                    "error": error
                    }
                return final_dict

            else:
                self.__write_error(r_path + "\n" + all_permissions)
                self.__print_exception()
                exit(0)



    # ==========================================================#
    # Purpose:  obtains ACL values for a single file / filepath # 
    #           given a dict object that contains Procmon.exe   #
    #           attributes/data                                 #
    # Return:   Dictionary                                      #
    # ==========================================================#
    def get_file_path_acl_procmon(self, path_dict):
        try:
            '''
            path_dict = {
                "proc_name" : proc_name, 
                "orig_cmd"  : orig_cmd, 
                "clean_cmd" : clean_cmd,
                "operation" : operation,
                "integrity" : integrity
                }
            '''
            path_dict = dict(path_dict)
            f_path = path_dict["clean_cmd"]

            # Working with weird WIndows/Procmon Output...
            if "|" in f_path:
                f_path = f_path.split("|")[0]

            if ("hklm" in f_path.lower() and "c:" in f_path.lower()):
                f_path = "C:/" + f_path.lower().split("c:")[1]

            acls = ""
            gfso = win32security.GetFileSecurity(
                f_path, win32security.DACL_SECURITY_INFORMATION
            )
            dacl = gfso.GetSecurityDescriptorDacl()

            for n_ace in range(dacl.GetAceCount()):
                ace = dacl.GetAce(n_ace)
                (ace_type, ace_flags) = ace[0]

                mask = 0  # Reset the bitmask for each interation
                domain = ""  # Reset the domain for each interation
                name = ""  # Reset the name for each interation
                ascii_mask = ""  # Reset the ascii permission value for each interation

                if ace_type in self.__CONVENTIONAL_ACES:
                    mask, sid = ace[1:]
                else:
                    mask, object_type, inherited_object_type, sid = ace[1:]

                name, domain, type = win32security.LookupAccountSid(None, sid)

                # Enumerate windows_security_enums
                for enum_obj in windows_objects.windows_security_enums:
                    if ctypes.c_uint32(mask).value == enum_obj.value.value:
                        access = self.__CONVENTIONAL_ACES.get(ace_type, "OTHER")
                        ascii_mask = enum_obj.name
                        acls += f"{domain}\\{name} {access} {ascii_mask}\n"

                # Enumerate nt_security_permissions
                for enum_obj in windows_objects.nt_security_enums:
                    if ctypes.c_uint32(mask).value == enum_obj.value.value:
                        access = self.__CONVENTIONAL_ACES.get(ace_type, "OTHER")
                        ascii_mask = enum_obj.name
                        acls += f"{domain}\\{name} {access} {ascii_mask}\n"

            acl_dict = {
                "process_name": path_dict["proc_name"],
                "integrity": path_dict["integrity"],
                "operation": path_dict["operation"],
                "original_cmd": path_dict["orig_cmd"],
                "path": f_path,
                "acls": acls}

            f_path = ""
            return acl_dict

        except Exception as e:
            error = str(e).lower()
            if (
                "find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
                or "nonetype" in error
            ):
                final_dict = {
                    "key_path":f_path,
                    "acls": "ERROR",
                    "error": error
                    }
                return final_dict

            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""

                final_dict = {
                    "key_path":f_path,
                    "acls": "ERROR",
                    "error": error
                    }
                return final_dict

            else:
                self.__write_error(f_path)
                self.__print_exception()
                exit(0)


    # ==========================================================#
    # Purpose:  Given a single path (directory or file),        #
    #           enumerate its corresponding ACL's.              #
    # Return:   Dictionary                                      #
    # ==========================================================#
    def get_file_path_acl(self, f_path):

        try:
            with windows_objects.disable_file_system_redirection():
                acls = []
                gfso = win32security.GetFileSecurity(
                    f_path, win32security.DACL_SECURITY_INFORMATION
                )
                dacl = gfso.GetSecurityDescriptorDacl()

                for n_ace in range(dacl.GetAceCount()):

                    ace = dacl.GetAce(n_ace)
                    (ace_type, ace_flags) = ace[0]

                    mask = 0            # Reset the bitmask for each interation
                    domain = ""         # Reset the domain for each interation
                    name = ""           # Reset the name for each interation
                    ascii_mask = ""     # Reset the ascii permission value for each interation

                    if ace_type in self.__CONVENTIONAL_ACES:
                        mask, sid = ace[1:]
                    else:
                        mask, object_type, inherited_object_type, sid = ace[1:]

                    name, domain, type = win32security.LookupAccountSid(None, sid)

                    # Enumerate windows_security_enums
                    for enum_obj in windows_objects.windows_security_enums:
                        if ctypes.c_uint32(mask).value == enum_obj.value.value:
                            access = self.__CONVENTIONAL_ACES.get(ace_type, "OTHER")
                            ascii_mask = enum_obj.name
                            acls.append(f"{domain}\\{name} {access} {ascii_mask}")

                    # Enumerate nt_security_permissions
                    for enum_obj in windows_objects.nt_security_enums:
                        if ctypes.c_uint32(mask).value == enum_obj.value.value:
                            access = self.__CONVENTIONAL_ACES.get(ace_type, "OTHER")
                            ascii_mask = enum_obj.name
                            acls.append(f"{domain}\\{name} {access} {ascii_mask}")

                final_acls = {
                    "file_path": f_path,
                    "acls": acls,
                    "error": None
                }
                return final_acls

        except Exception as e:
            error = str(e).lower()
            if ("find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
                or "nonetype" in error
                or "trust relationship" in error):

                error_dict = {
                    "path_name": f_path,
                    "acls": acls,
                    "error": error
                }
                return error_dict

            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""

                error_dict = {
                    "path_name": f_path,
                    "acls": note,
                    "error": error
                }
                return error_dict

            else:
                self.__write_error(f_path)
                self.__print_exception()
                exit(0)


    # ==========================================================#
    # Purpose:  Given an SDDL DACL String, parse it and analyze #
    #           the overall permission set for each user and    # 
    #           group                                           #
    #                                                           #
    # Return: Dict of all permissions in SDDL                   #
    # ==========================================================#
    def __sddl_dacl_parse(self, sddl_string):
        try:

            # We already know we have obtained the DACL SDDL string via win32security. Therefore
            # we do not have to enumerate the SDDL type even though we prove such data in the
            # windows_objects.SDDL() class.

            all_permissions = {}
            sddl_permissions = re.findall(self.re_perms, sddl_string)

            for dacl in sddl_permissions:

                # There are some odd dacl windows-isms here that I need to account for:
                if "WIN://" not in dacl:

                    raw_ace_type = dacl.split(";")[0]
                    raw_ace_flags = dacl.split(";")[1]
                    raw_perms = dacl.split(";")[2]
                    raw_trustee = dacl.split(";")[5]

                    # Obtain the Plaintext ACE Type:
                    access_type = self.ACCESS[raw_ace_type]

                    # Obtain the plaintext ACE Flags: Don't Need These
                    """
                    flags = ""
                    flags_index = 0
                    if (len(raw_ace_flags) > 2):
                      flag_split = [raw_ace_flags[i:i+2] for i in range(0, len(raw_ace_flags), 2)]
                      for flag in flag_split:
                        if (flags_index == 0):
                          flags += f"{self.ACCESS[flag]}"
                          flags_index += 1
                        else:
                          flags += f", {self.ACCESS[flag]}"
                    else:
                      flags += f"{self.ACCESS[raw_ace_flags]}"
                    """

                    # Obtain the plaintext permissions:
                    acls = ""
                    acl_index = 0
                    # Check if we have HEX permissions first:
                    if "0x" in raw_perms:
                        raw_perms = self.__access_from_hex(raw_perms)
                    # Plaintext Permission Set:
                    if len(raw_perms) > 2:
                        perm_split = [
                            raw_perms[i : i + 2] for i in range(0, len(raw_perms), 2)
                        ]
                        for acl in perm_split:
                            if acl_index == 0:
                                acls += f"{self.ACCESS[acl]}"
                                acl_index += 1
                            else:
                                acls += f", {self.ACCESS[acl]}"
                    else:
                        acls += f"{self.ACCESS[raw_perms]}"

                    # Obtain the Account/User (Trustee)
                    try:  # sometimes fails due to undocumented trustees such as services.
                        if len(raw_trustee) <= 2:
                            trustee = self.TRUSTEE[
                                raw_trustee
                            ]  # Get the trustee from the windows_objects class
                        else:
                            try:  # if the object is a SID, attempt to translate it and obtain the ASCII name
                                trustee = win32security.LookupAccountSid(
                                    None, win32security.GetBinarySid(raw_trustee)
                                )
                                trustee = f"{trustee[1]}/{trustee[0]}"
                            except:
                                trustee = None
                    except:
                        trustee = None

                    # Add all the content to the dict object
                    if trustee not in all_permissions.keys() and trustee != None:
                        all_permissions[trustee] = acls
                    elif trustee != None:
                        current = f"{str(all_permissions[trustee])} {acls}"
                        all_permissions[trustee] = current
                        current = ""

            return all_permissions

        except Exception as e:
            self.__write_error(sddl_string + "\n" + dacl)
            self.__print_exception()
            pass


    # ==========================================================#
    # Purpose:Check for suspect permission sets                 #
    # Return: Boolean                                           #
    #   - True: Found suspect Permission                        #
    #   - False: benign                                         #
    # ==========================================================#
    def __check_permission(self, line):
        try:
            line = line.lower()
            tmp = False
            users = [self.__username, "users", "everyone", "interactive", "authenticated"]
            permissions = [
                "fullcontrol",
                "write",
                "write_dac",
                "generic_write",
                "key_write",
                "write_owner",
                "service_change_config",
                "changepermissions",
                "takeownership",
                "traverse",
                "key_all_access",
                "file_all_access",
                "all_access",
                "file_generic_write",
                "generic_all"
            ]

            for user in users:
                for permission in permissions:
                    if user in line.lower() and permission in line.lower():
                        tmp = True
                        break

                if tmp:
                    break

            return tmp

        except Exception as e:
            self.__print_exception()


    # ==============================================#
    # Purpose: Given a hex permission bitmask,      #
    # translate it into an ASCII two-byte denoting  #
    # in order to analyze further.                  #
    #                                               #
    # Return: String - Contains ACCESS strings      #
    # ==============================================#
    def __access_from_hex(self, hex):

        hex = int(hex, 16)
        rights = ""

        for spec in self.ACCESS_HEX.items():
            if hex & spec[0]:
                rights += spec[1]

        return rights



    # ===============================================#
    # Purpose: Write errors to File                  #
    # Return: None                                   #
    # ===============================================#
    def __write_error(self, data):
        try:

            self.__error_out_file.write(data)

        except Exception as e:
            self.__print_exception()
            exit(1)


    # ==============================================#
    # Purpose: Clean Exception Printing             #
    # Return: None                                  #
    # ==============================================#
    def __print_exception(self):
      self.error_index += 1
      exc_type, exc_obj, tb = sys.exc_info()
      tmp_file = tb.tb_frame
      lineno = tb.tb_lineno
      filename = tmp_file.f_code.co_filename
      linecache.checkcache(filename)
      line = linecache.getline(filename, lineno, tmp_file.f_globals)
      sep = "-" * 100
      data = f"\n\nREGISTRY EXCEPTION IN: {filename}\n\t[i] LINE: {lineno}, {line.strip()}\n\t[i] OBJECT: {exc_obj}\n{sep}\n"
      self.__write_error(data)