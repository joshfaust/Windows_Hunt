import pandas as pd
import subprocess
import os
import re
import time
import threading
import argparse
import csv
import openpyxl
from tqdm import tqdm

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

#=======================================#
# Pulls ACLS for all cleaned keys       #
#=======================================#
## aggregateCommands --> threadCommands --> runCommands --> writeToFile
def aggregateCommands(o_dir, total_threads):
    global mutex
    num_lines = sum(1 for line in open(f'{o_dir}/cleaned_keys.txt'))
    commands = [None] * total_threads
    commands_index = 0

    pbar = tqdm(total=num_lines)
    pbar.set_description("Analyzing ACL's")

    with open(f"{o_dir}/cleaned_keys.txt", "r") as f:
        for path in f:
            path = path.strip()
            cmd = f"powershell.exe -exec bypass \"Get-Acl '{path}' | format-list\""

            # Send the commands list to the threading function each time it fills up with new registry keys.
            if (commands_index == total_threads):
                while (mutex.locked()):
                    time.sleep(1)
                threadCommands(commands)
                commands_index = 0
                pbar.update(total_threads)
            else:
                commands[commands_index] = cmd
                commands_index += 1
    pbar.close()
    return num_lines

#=======================================#
# Thread the Powershell ACL lookups     #
#=======================================#
def threadCommands(commands):
    global mutex
    threads = []
    tot_commands = len(commands)

    for i in range(tot_commands):
        t = threading.Thread(target=runCommands, args=(commands[i],))
        t.start()
        threads.append(t)
        if (i == (tot_commands - 1)):
            t.join()

#=======================================#
# Runs any command called in new thread #
#=======================================#
def runCommands(cmd):
    global mutex
    data = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = data.communicate()
    writeToFile(cmd, out)

#=======================================#
# Write to File Function for threads    #
#=======================================#
def writeToFile(command, data):
    global mutex, aclOutFile
    try:
        # wait until the file is unlocked.
        while (mutex.locked()):
            time.sleep(1)

        mutex.acquire()
        aclOutFile.write(str(command).encode("utf-8") + b"\n")
        aclOutFile.write(data)
        aclOutFile.write(b"-" * 140 + b"\n")
        mutex.release()
    except Exception as e:
        print(f"[!] ERROR: {e}")
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

            # Make sure this is not a duplicate key before saving
            if (clean_path not in previous_paths):
                # Save key to cleaned keys:
                keyOutFile.write(clean_path + "\n")

                pbar.update(1)

            else:
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
            aclOutFile = open(f"{args.o}/acls.txt", "wb")

            # Start the Enumeration. 
            procmonInputAnalysis(args.p, args.o)                        # Analyze the Procmon CSV File and pull out paths
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
        print(f"[!] Error: {e}")
        exit(1)
