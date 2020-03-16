import pandas as pd
import subprocess
import os
import sys
import re
import time
import threading
import argparse
import csv
import linecache
import openpyxl
import ctypes
import win32security
import win32api
import win32con as con
from colorama import Fore, init
from pathlib import Path
from enum import Enum
from tqdm import tqdm
init()

#---------------------------------------------------#
# Windows Process Information:                      #
# This script / set of scripts is dedicated to      #
# hunting for insecure process registry keys that   #
# could possible be used for privilege escallation  #
# and code execution purposes.                      #
#                                                   #
# Author: @Jfaust0                                  #
# Site: SevroSecurity.com                           #
#---------------------------------------------------#

# GLOBAL VARIABLES
global mutex, aclOutFile


class windows_security_enums(Enum):
    FullControl               =   ctypes.c_uint32(0x1f01ff)
    modify                    =   ctypes.c_uint32(0x0301bf)
    ReadExecAndSynchronize    =   ctypes.c_uint32(0x1200a9)
    Synchronize               =   ctypes.c_uint32(0x100000)
    ReadAndExecute            =   ctypes.c_uint32(0x0200a9)
    ReadAndWrite              =   ctypes.c_uint32(0x02019f)
    Read                      =   ctypes.c_uint32(0x020089)
    Write                     =   ctypes.c_uint32(0x000116)

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

CONVENTIONAL_ACES = {
  win32security.ACCESS_ALLOWED_ACE_TYPE : "ALLOW", 
  win32security.ACCESS_DENIED_ACE_TYPE : "DENY"
}


def get_acl_list(path):
    try:
        print(path)
        # If the path is a Registry key, do something very different:
        if ("hklm" in path.lower()):
            path = path.split(":\\")[1]
            key = win32api.RegOpenKey(con.HKEY_LOCAL_MACHINE, path, 0,  con.KEY_ENUMERATE_SUB_KEYS | con.KEY_QUERY_VALUE | con.KEY_READ)
            sd = win32api.RegGetKeySecurity(key, win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            owner_sid = sd.GetSecurityDescriptorOwner()

            for n_ace in range (dacl.GetAceCount()):
                ace = dacl.GetAce (n_ace)
                (ace_type, ace_flags) = ace[0]

                mask = 0
                domain = ""
                name = ""
                ascii_mask = ""
                acls = ""

                if ace_type in CONVENTIONAL_ACES:
                    mask, sid = ace[1:]
                else:
                    mask, object_type, inherited_object_type, sid = ace[2]

                name, domain, type = win32security.LookupAccountSid (None, owner_sid)
                sddl_string = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)

                pwrshell_cmd = f"powershell.exe -exec bypass (ConvertFrom-SddlString -Sddl '{sddl_string}').DiscretionaryAcl"
                data = subprocess.Popen(pwrshell_cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = data.communicate()
                out = out.decode("utf-8")

                final = (f"Path  : {path}\n{out}\n")
                writeToFile(final)

        # If the path is a file/folder path:
        else:

            acls = "Access  : "
            gfso = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
            dacl = gfso.GetSecurityDescriptorDacl()

            for n_ace in range (dacl.GetAceCount()):
                ace = dacl.GetAce (n_ace)
                (ace_type, ace_flags) = ace[0]

                mask = 0
                domain = ""
                name = ""
                ascii_mask = ""

                if ace_type in CONVENTIONAL_ACES:
                    mask, sid = ace[1:]
                else:
                    mask, object_type, inherited_object_type, sid = ace[1:]

                name, domain, type = win32security.LookupAccountSid (None, sid)

                # Enumerate windows_security_enums
                for enum_obj in windows_security_enums:
                    if (ctypes.c_uint32(mask).value == enum_obj.value.value):
                        access = CONVENTIONAL_ACES.get (ace_type, "OTHER")
                        ascii_mask = enum_obj.name
                        acls += (f"{domain}\\{name} {access} {ascii_mask}\n")

                # Enumerate nt_security_permissions
                for enum_obj in nt_security_enums:
                    if (ctypes.c_uint32(mask).value == enum_obj.value.value):
                        access = CONVENTIONAL_ACES.get (ace_type, "OTHER")
                        ascii_mask = enum_obj.name
                        acls += (f"{domain}\\{name} {access} {ascii_mask}\n")

            data = (f"\nPath  : {path}\n{acls}\n")
            writeToFile(data)

    except Exception as e:
        print("=" * 100)
        print(path)
        print("=" * 100)
        print_exception()
        pass


#=======================================#
# Pulls ACLS for all cleaned keys       #
#=======================================#
## aggregateCommands --> threadCommands --> runCommands --> writeToFile
def aggregateCommands(o_dir, total_threads):
    global mutex
    total_number_of_paths = sum(1 for line in open(f'{o_dir}/cleaned_keys.txt'))
    commands = [None] * total_threads
    commands_index = 0
    total_commands_sent = 0

    pbar = tqdm(total=total_number_of_paths)
    pbar.set_description("Analyzing ACL's")

    with open(f"{o_dir}/cleaned_keys.txt", "r") as f:

        for path in f:  # For each object in cleaned keys
            
            commands_left = total_number_of_paths - total_commands_sent
            path = path.strip()
            cmd = path

             # If the number of commands loaded into commands == # of threads
            if (commands_index == total_threads):      

                while (mutex.locked()):                 # While there is a mutex lock, sleep for 1 second.
                    time.sleep(1)

                threadCommands(commands)                # Send the next list of commands
                commands_index = 0                      # Reset the commands index counter to 0 to start loading new commands
                pbar.update(total_threads)              # Updates the progress bar

                # If the number of commands (paths) are less than the allocated threads, decrese and send the last commands
                if (commands_left < total_threads):
                    commands = [None] * commands_left   # commands list length reset to number of commands left
                    total_threads = commands_left       # total_threads reset to number of commands left

            else:
                commands[commands_index] = cmd
                commands_index += 1
                total_commands_sent += 1

    pbar.close()
    return total_number_of_paths

#=======================================#
# Thread the Powershell ACL lookups     #
#=======================================#
def threadCommands(commands):
    global mutex
    threads = []
    tot_commands = len(commands)

    for i in range(tot_commands):
        t = threading.Thread(target=get_acl_list, args=(commands[i],))
        t.daemon = True
        t.start()
        threads.append(t)
        if (i == (tot_commands - 1)):
            t.join()

#=======================================#
# Write to File Function for threads    #
#=======================================#
def writeToFile(data):
    global mutex, aclOutFile
    try:
        # wait until the file is unlocked.
        while (mutex.locked()):
            time.sleep(1)

        mutex.acquire()
        aclOutFile.write(data)
        aclOutFile.write("-" * 100)
        mutex.release()
    except Exception as e:
        print_exception()
        exit(1)

#=======================================#
# Analyze Raw ProcMon output            #
#=======================================#
def procmonInputAnalysis(p_file, o_dir):
    bad_process_names = ["conhost.exe", "dem.exe", "svchost.exe"]  # Names we do not want to enumerate
    bad_operation_names = ["regclosekey", "regqueryvalue", "regenumvalue", "regquerykeysecurity",
                           "regquerykey"]  # Operations we don't care about

    keyOutFile = open(f"{o_dir}/cleaned_keys.txt", "w") #Save the cleanup output to a file. 

    # DataFrame Objects
    data = pd.read_csv(p_file)
    headers = list(data)
    dataframe_length = data.shape[0]

    pbar = tqdm(total=dataframe_length)
    pbar.set_description("Analyzing Procmon Data")
    previous_paths = set()           # Designed to remove saving duplicate key paths (Save only 5 paths)

    for i in range(0, dataframe_length):
        # Pull in dataframe content we're interested in.
        path = str(data['Path'][i]).lower()
        proc_name = str(data['Process Name'][i]).lower()
        operation = str(data['Operation'][i]).lower()

        if (proc_name not in bad_process_names and operation not in bad_operation_names):
            
            if (".exe" not in path and ".dll" not in path):
                # Cleanup Registry Key Path
                dir_count = len(re.findall(r'\\', path))
                path = path.split("\\")
                clean_path = ""

                for j in range(0, dir_count):
                    if (j == (dir_count-1)):
                        clean_path += path[j]
                    elif (j == 0):
                        clean_path += path[j] + ":\\"
                    else:
                        clean_path += path[j] + "\\"
            else:
                # Send the .DLL/.EXE to be analyzed. 
                clean_path = path
                base_path = os.path.dirname(clean_path)

            # Make sure this is not a duplicate key before saving
            if (clean_path not in previous_paths):
                # Save key to cleaned keys
                keyOutFile.write(clean_path + "\n")
                previous_paths.add(clean_path)

            if ((".exe" in clean_path.lower() or ".dll" in clean_path.lower()) and base_path not in previous_paths):
                keyOutFile.write(base_path + "\n")
                previous_paths.add(base_path)

            pbar.update(1)

        else:
            pbar.update(1)

    pbar.close()
    keyOutFile.close()

#=======================================#
# Look for objective issues             #
#=======================================#
def analyze_acls(o_dir):
    df = pd.DataFrame(columns=["key", "owner", "group", "access"])
    num_lines = sum(1 for line in open(f'{o_dir}/acls.txt'))

    with open(f"{o_dir}/acls.txt", "r") as f:
        permission_index = 0        # Index of determining number of permissions between Access and Audit
        total_index = 0             # Index of all frames we have built
        fun_index = 0               # Index of Full_Control Registry Keys
        key = None                  # Placeholder for key
        owner = None                # Placeholder for owner
        group = None                # Placeholder for group
        access = []                 # Placeholder for access control list
        add = False   # Placeholder to determine if user has full permissions
        pbar = tqdm(total=num_lines)
        pbar.set_description("Looking for Evil")

        for line in f:
            try:
                # Determine Path
                if ("path" in line.lower()):
                    key = str(line.split(": ")[1]).strip()

                # Determine Owner
                if ("owner" in line.lower()):
                    owner = str(line.split(": ")[1]).strip()

                # Determine Group
                if ("group" in line.lower()):
                    group = str(line.split(": ")[1]).strip()

                # Determine Access
                if (permission_index >= 1 and ":" not in line.lower() and "------" not in line.lower()):
                    access.append(str(line).strip())
                    permission_index += 1
                    user_full_control = check_permission(line)
                    if (user_full_control):
                        add = True

                if ("access" in line.lower()):              # Check if we are at the ACCESS portion:
                    access.append(str(line.split(": ")[1]).strip())
                    permission_index += 1                   # Denote which permission we are at
                    user_full_control = check_permission(line)
                    if (user_full_control):
                        add = True

                #if ("----" in line.lower() and key != None and owner != None and group != None and len(access) > 1):
                if ("-------" in line.lower()):
                    str_access = str(access)

                    if (add):
                        df = df.append({"key": key, "owner": owner, "group": group, "access": str_access}, ignore_index=True)
                        fun_index += 1

                    path = None
                    owner = None
                    group = None
                    add = False
                    permission_index = 0
                    total_index += 1
                    access.clear()

                pbar.update(1)

            except Exception as e:
                pass
                pbar.update(1)

        df.to_excel(f"{o_dir}/data.xlsx")
        pbar.close()
        
    return fun_index

#=======================================#
# Look for objective issues             #
#=======================================#
def analyze_acls_from_file(o_dir, file):
    df = pd.DataFrame(columns=["key", "owner", "group", "access"])
    num_lines = sum(1 for line in open(file))

    with open(file, "r") as f:
        permission_index = 0        # Index of determining number of permissions between Access and Audit
        total_index = 0             # Index of all frames we have built
        fun_index = 0               # Index of Full_Control Registry Keys
        key = None                  # Placeholder for key
        owner = None                # Placeholder for owner
        group = None                # Placeholder for group
        access = []                 # Placeholder for access control list
        add = False   # Placeholder to determine if user has full permissions
        pbar = tqdm(total=num_lines)
        pbar.set_description("Looking for Evil")

        for line in f:
            try:
                # Determine Path
                if ("path" in line.lower()):
                    key = str(line.split(": ")[1]).strip()

                # Determine Owner
                if ("owner" in line.lower()):
                    owner = str(line.split(": ")[1]).strip()

                # Determine Group
                if ("group" in line.lower()):
                    group = str(line.split(": ")[1]).strip()

                # Determine Access
                if (permission_index >= 1 and ":" not in line.lower() and "------" not in line.lower()):
                    access.append(str(line).strip())
                    permission_index += 1
                    user_full_control = check_permission(line)
                    if (user_full_control):
                        add = True

                if ("access" in line.lower()):              # Check if we are at the ACCESS portion:
                    access.append(str(line.split(": ")[1]).strip())
                    permission_index += 1                   # Denote which permission we are at
                    user_full_control = check_permission(line)
                    if (user_full_control):
                        add = True

                #if ("----" in line.lower() and key != None and owner != None and group != None and len(access) > 1):
                if ("-------" in line.lower()):
                    str_access = str(access)

                    if (add):
                        df = df.append({"key": key, "owner": owner, "group": group, "access": str_access}, ignore_index=True)
                        fun_index += 1

                    path = None
                    owner = None
                    group = None
                    add = False
                    permission_index = 0
                    total_index += 1
                    access.clear()

                pbar.update(1)

            except Exception as e:
                pass
                pbar.update(1)

        df.to_excel(f"{o_dir}/data.xlsx")
        pbar.close()
        
    return fun_index

# Check the permissions of an object
def check_permission(line):
    tmp = False
    users = ["users", "everyone", "interactive", "authenticated"]
    permissions = ["fullcontrol", "write", "changepermissions", "takeownership", "traverse"]

    for user in users:
        for permission in permissions:
            if (user in line.lower() and permission in line.lower()):
                tmp = True
                break
        if (tmp):
            break

    return tmp

# remove duplicates from a file. 
def remove_duplicates_from_file(f_path, o_path):
    lines_seen = set()
    out = f"{o_path}/{os.path.basename(f_path)}.cleaned"
    outfile = open(out, "w")
    for line in open(f_path, "r"):
        line = line.strip()
        if (line not in lines_seen):
            outfile.write(line + "\n")
            lines_seen.add(line)
    outfile.close()

def clean_path(p):
    outpath = re.sub(r"[\\]", r"\\\\", p)
    outpath = re.sub(r"[/]", r"\\\\", outpath)
    return outpath


def print_exception():
    exc_type, exc_obj, tb = sys.exc_info()
    tmp_file = tb.tb_frame
    lineno = tb.tb_lineno
    filename = tmp_file.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, tmp_file.f_globals)
    print(
        f"{Fore.RED}EXCEPTION IN: {Fore.GREEN}{filename}\n\t[i] LINE: {lineno}, {line.strip()}\n\t[i] OBJECT: {exc_obj}{Fore.RESET}"
    )


#=======================================#
# MAIN                                  #
#=======================================#
if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        me = parser.add_mutually_exclusive_group()
        me.add_argument("-p", "--procmon", dest="p", default=None, metavar='', required=False, help="Path to the Procmon Output File (CSV)")
        me.add_argument("-a", "--acl", dest="acl", default=None, metavar='', required=False, help="Analyze a singluar acls.txt file")
        parser.add_argument("-t", "--threads", dest="threads",  type=int, default=10, required=False, help="Defined number of threads (Max 100). Default=10")
        parser.add_argument("-o", "--out", dest="o", metavar='', required=True, help="Output location for results.")
        args = parser.parse_args()


        # Check to make sure output path is valid:
        if (not os.path.exists(args.o)):
            print(f"[!] {args.o} does not exist")
            exit(1)

        if (args.p != None):
            # Check to make sure Procmon File is CSV:
            with open(args.p, "r") as f:
                if (not csv.Sniffer().has_header(f.read(2014))):
                    print(f"[!] {str(args.p).strip()} is not a CSV file.")
                    exit(1)

            # Initialize the Global Variables
            mutex = threading.Lock()
            aclOutFile = open(f"{args.o}/acls.txt", "w")

            # Start the Enumeration. 
            #procmonInputAnalysis(args.p, args.o)                        # Analyze the Procmon CSV File and pull out paths
            total_analyzed = aggregateCommands(args.o, args.threads)    # Send paths to aggregateCommands with totla Thread Count
            aclOutFile.close()
            interesting_items = analyze_acls(args.o)

            print('-' * 125)
            print(f"\n[i] A total of {total_analyzed} Registy Keys Were Analyzed.")
            print(f"[i] {interesting_items} Were found to be improperly configured.")
            print("[i] Output Files:")
            print(f"\t+ {args.o}acls.txt:\t\tRaw output of Access Control Listings")
            print(f"\t+ {args.o}cleaned_keys.txt:\tClean verions (no duplicates) or the Procmon Output")
            print(f"\t+ {args.o}data.xlsx:\t\tKeys denoted as improperly configured/interesting")
            
        if (args.acl != None):
            interesting_items = analyze_acls_from_file(args.o, args.acl)
            print('-' * 125)
            print(f"[i] {interesting_items} Were found to be improperly configured.")
            print("[i] Output Files:")
            print(f"\t+ {args.o}data.xlsx:\t\tKeys denoted as improperly configured/interesting")
            
        exit(0)

    except Exception as e:
        print_exception()
        exit(1)
