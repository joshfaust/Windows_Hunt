import sys
import os
import re
import ctypes
import time
import threading
import win32security
import win32api
import linecache
import numpy
import win32con as con
from colorama import Fore, init
from enum import Enum
from . import windows_objects

init()

# ---------------------------------------------------#
# Name:     Registry Enumeration Class              #
# Purpose:  Conduct the overall DACL analysis       #
# Author:   @jfaust0                                #
# Website:  sevrosecurity.com                       #
# ---------------------------------------------------#


class registry_enumeration:
    def __init__(self, o_dir):
        self.name = "Registry Enumeration"
        self.error_index = 0
        self.re_valid_string = re.compile("^[ADO][ADLU]?\:\(.*\)$")
        self.re_perms = re.compile("\(([^\(\)]+)\)")
        self.re_type = re.compile("^[DOGS]")
        self.re_owner = re.compile("^O:[^:()]+(?=[DGS]:)")
        self.re_group = re.compile("G:[^:()]+(?=[DOS]:)")
        self.re_acl = re.compile("[DS]:.+$")
        self.re_const = re.compile("(\w\w)")
        self.re_non_acl = re.compile("[^:()]+$")
        self.SDDL_OBJECT = windows_objects.SDDL()
        self.ACCESS = self.SDDL_OBJECT.ACCESS
        self.SDDL_TYPE = self.SDDL_OBJECT.SDDL_TYPE
        self.TRUSTEE = self.SDDL_OBJECT.TRUSTEE
        self.ACCESS_HEX = self.SDDL_OBJECT.ACCESS_HEX
        self.__output_dir = o_dir
        self.__acl_out_file = open(f"{self.__output_dir}/raw_acls.txt", "a+")
        self.__error_out_file = open(f"{self.__output_dir}/errors.txt", "a+")
        self.__mutex = threading.Lock()
        self.__error_mutex = threading.Lock()
        self.__CONVENTIONAL_ACES = {
            win32security.ACCESS_ALLOWED_ACE_TYPE: "ALLOW",
            win32security.ACCESS_DENIED_ACE_TYPE: "DENY",
        }

    # ===============================================#
    # Purpose: Obtains ACL values for a single      #
    # Registry path / key                           #
    # Return: None                                  #
    # ===============================================#
    def get_acl_list_procmon(self, path_dict):
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

            path_dict = dict(path_dict)
            r_path = path_dict["clean_cmd"]

            try:
                path = r_path.split(":\\")[1]
            except:
                path = r_path.split("hklm\\")[1]

            key = win32api.RegOpenKey(
                con.HKEY_LOCAL_MACHINE,
                path,
                0,
                con.KEY_ENUMERATE_SUB_KEYS | con.KEY_QUERY_VALUE | con.KEY_READ,
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
            all_permissions = dict(self.sddl_dacl_parse(sddl_string))

            keys = all_permissions.keys()
            acls = ""
            for key in keys:
                acls += f"{key}: {all_permissions[key]}\n"
            
            data = f"""
Process_Name: {path_dict["proc_name"]}
Integrity: {path_dict["integrity"]}
Operation: {path_dict["operation"]}
Original_Cmd: {path_dict["orig_cmd"]}
Path: {r_path}
Access: {acls}
            """

            self.__write_acl(data)

        except Exception as e:
            error = str(e).lower()
            if (
                "find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
            ):
                data = f"\nPath: {r_path}\n{str(e)}\n"
                self.__write_acl(data)
                pass
            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""
                data = f"\nPath: {r_path}\n{note}\n"
                self.__write_acl(data)
                pass
            else:
                self.__write_error(r_path + "\n" + all_permissions)
                self.__print_exception()
                exit(0)

    # ===============================================#
    # Purpose: Given an SDDL DACL String, parse it  #
    # and analyze the overall permission set for    #
    # each user and group                           #
    #                                               #
    # Return: Dict of all permissions in SDDL       #
    # ===============================================#
    def sddl_dacl_parse(self, sddl_string):
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
            self.error_index += 1
            self.__write_error(sddl_string + "\n" + dacl)
            self.__print_exception()
            pass

    # ===============================================#
    # Purpose: Given a hex permission bitmask,      #
    # translate it into an ASCII two-byte denoting  #
    # in order to analyze further.                  #
    #                                               #
    # Return: String - Contains ACCESS strings      #
    # ===============================================#
    def __access_from_hex(self, hex):

        hex = int(hex, 16)
        rights = ""

        for spec in self.ACCESS_HEX.items():
            if hex & spec[0]:
                rights += spec[1]

        return rights

    # ===============================================#
    # Purpose: Write to File Function for threads   #
    # Return: None                                  #
    # ===============================================#
    def __write_acl(self, data):
        try:
            # wait until the file is unlocked.
            while self.__mutex.locked():
                time.sleep(1)

            self.__mutex.acquire()
            self.__acl_out_file.write(data)
            self.__acl_out_file.write("--------END--------\n")
            self.__mutex.release()

        except Exception as e:
            self.__print_exception()
            exit(1)

    # ===============================================#
    # Purpose: Write errors to File                  #
    # Return: None                                   #
    # ===============================================#
    def __write_error(self, data):
        try:
            # wait until the file is unlocked.
            while self.__error_mutex.locked():
                time.sleep(1)

            self.__error_mutex.acquire()
            self.__error_out_file.write(data)
            self.__error_mutex.release()

        except Exception as e:
            self.__print_exception()
            exit(1)


    # ===============================================#
    # Purpose: Clean Exception Printing             #
    # Return: None                                  #
    # ===============================================#
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

