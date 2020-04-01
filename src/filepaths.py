import sys
import os
import io
import glob
import ctypes
import time
import threading
import win32security
import win32api
import linecache
import win32con as con
from colorama import Fore, init
from enum import Enum
from . import windows_objects

init()

# --------------------------------------------------#
# Name:     File/Filepath Enumeration Class         #
# Purpose:  Conduct the overall DACL analysis       #
# Author:   @jfaust0                                #
# Website:  sevrosecurity.com                       #
# --------------------------------------------------#


class filepath_enumeration:
    def __init__(self, o_dir, initialize):
        self.name = "Filepath Enumeration"
        self.error_index = 0
        self.__output_dir = o_dir
        self.__mutex = threading.Lock()
        self.__error_mutex = threading.Lock()
        self.__CONVENTIONAL_ACES = {
            win32security.ACCESS_ALLOWED_ACE_TYPE: "ALLOW",
            win32security.ACCESS_DENIED_ACE_TYPE: "DENY",
        }        
        if (initialize):
            self.__acl_out_file = io.open(f"{self.__output_dir}/raw_acls.txt", "a+", encoding="utf8")
            self.__error_out_file = io.open(f"{self.__output_dir}/errors.txt", "a+", encoding="utf8")

    # ==============================================#
    # Purpose: Writes ACL values for a single file  #
    # or filepath given a dict object that contains #
    # Procmon.exe attributes/data                   #
    # Return: None                                  #
    # ==============================================#
    def get_acl_list_procmon(self, path_dict):
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

            data = f"""
Process_Name: {path_dict["proc_name"]}
Integrity: {path_dict["integrity"]}
Operation: {path_dict["operation"]}
Original_Cmd: {path_dict["orig_cmd"]}
Path: {f_path}
Access: {acls}
            """
            self.__write_acl(data)
            f_path = ""

        except Exception as e:
            error = str(e).lower()
            if (
                "find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
                or "nonetype" in error
            ):

                data = f"\nPath: {f_path}\n{str(e)}\n"
                self.__write_acl(data)
                pass

            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""

                data = f"\nPath: {f_path}\n{note}\n"
                self.__write_acl(data)
                pass

            else:
                self.__write_error(f_path)
                self.__print_exception()
                exit(0)

    # ==============================================#
    # Purpose: Writes ACL values for all files      #
    # (recursive directory search) given a path     #
    # Return: None                                  #
    # ==============================================#
    def get_acl_list_path(self, f_path):

        try:
            with windows_objects.disable_file_system_redirection():
                acls = "Access: "
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

                data = f"\nPath: {f_path}\n{acls}\n"
                self.__write_acl(data)

        except Exception as e:
            error = str(e).lower()
            if (
                "find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
                or "nonetype" in error
            ):

                data = f"\nPath: {f_path}\n{str(e)}\n"
                self.__write_acl(data)
                pass

            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""

                data = f"\nPath: {f_path}\n{note}\n"
                self.__write_acl(data)
                pass

            else:
                self.__write_error(f_path)
                self.__print_exception()
                exit(0)


    # ==============================================#
    # Purpose: Returns ACL values for all files     #
    # (recursive directory search) given a path     #
    # Return: List of ACLs                          #
    # ==============================================#
    def get_acl_list_return(self, f_path):

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
                            acls.append(f"{domain}\\{name} {access} {ascii_mask}")

                    # Enumerate nt_security_permissions
                    for enum_obj in windows_objects.nt_security_enums:
                        if ctypes.c_uint32(mask).value == enum_obj.value.value:
                            access = self.__CONVENTIONAL_ACES.get(ace_type, "OTHER")
                            ascii_mask = enum_obj.name
                            acls.append(f"{domain}\\{name} {access} {ascii_mask}")

                return acls

        except Exception as e:
            error = str(e).lower()
            if (
                "find the path specified" in error
                or "find the file specified" in error
                or "access is denied" in error
                or "ace type 9" in error
                or "nonetype" in error
            ):
                acls.append(str(e))
                pass
                return acls

            elif "no mapping" in error:
                note = """Possibly VULNERABLE: No mapping between account names and SID's
        Account used to set GPO may have been removed
        Account name may be typed incorrectly
        INFO: https://www.rebeladmin.com/2016/01/how-to-fix-error-no-mapping-between-account-names-and-security-ids-in-active-directory/"""

                acls.append(str(e))
                pass
                return acls

            else:
                self.__write_error(f_path)
                self.__print_exception()
                exit(0)

    # ==============================================#
    # Purpose: Write to File Function for threads   #
    # Return: None                                  #
    # ==============================================#
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
        data = f"\n\nFILE EXCEPTION IN: {filename}\n\t[i] LINE: {lineno}, {line.strip()}\n\t[i] OBJECT: {exc_obj}\n{sep}\n"
        self.__write_error(data)


    # ==============================================#
    # Purpose: Remove duplicate entries in txt file #
    # Return: None                                  #
    # ==============================================#
    def __remove_duplicates_from_file(self, f_path, o_path):
        lines_seen = set()
        out = f"{o_path}/{os.path.basename(f_path)}.cleaned"
        outfile = open(out, "w")
        for line in open(f_path, "r"):
            line = line.strip()
            if line not in lines_seen:
                outfile.write(line + "\n")
                lines_seen.add(line)
        outfile.close()
