import sys
import os
import re
import time
import getpass
import threading
import linecache
import pandas as pd
from . import filepaths
from . import registry
from . import windows_objects
from tqdm import tqdm
from colorama import Fore, init

init()

# ---------------------------------------------------#
# Name:     Analysis Class                          #
# Purpose:  Conduct the overall DACL analysis       #
# Author:   @jfaust0                                #
# Website:  sevrosecurity.com                       #
# ---------------------------------------------------#


class analyze:
    def __init__(self, o_dir):
        self.name = "Analysis"
        self.__output_dir = o_dir
        self.__final_report = f"{self.__output_dir}/evil.xlsx"
        self.__reg_enum = registry.registry_enumeration(self.__output_dir)
        self.__file_enum = filepaths.filepath_enumeration(self.__output_dir)
        self.__username = str(getpass.getuser()).lower()

    # ===============================================#
    # Purpose: loads raw procmon csv output into a  #
    # Pandas dataframe, removed duplicates, and     #
    # outputs all cleaned / de-duplicated objects   #
    # to cleaned_paths.txt                          #
    # Return: None                                  #
    # ===============================================#
    def parse_procmon_csv(self, p_file):
        try:
            # Names we do not want to enumerate
            bad_process_names = [
                "conhost.exe",
                "dem.exe",
                "svchost.exe",
            ]  
            # Operations we don't care about
            bad_operation_names = [
                "regclosekey",
                "regqueryvalue",
                "regenumvalue",
                "regquerykeysecurity",
                "regquerykey",
            ]  # Operations we don't care about

            cleaned_data_file = open(f"{self.__output_dir}/cleaned_paths.csv", "w")  # Save the cleanup output to a file.
            cleaned_data_file.write("Process Name,Original Path,Clean Path,Operation,Integrity\n")

            # DataFrame Objects
            data = pd.read_csv(p_file)
            headers = list(data)
            dataframe_length = data.shape[0]

            pbar = tqdm(total=dataframe_length)
            pbar.set_description("Analyzing Procmon Data")
            previous_paths = (set())  
            path = ""

            for i in range(0, dataframe_length):

                # Pull in dataframe content we're interested in.
                orig_path = str(data["Path"][i]).lower()
                proc_name = str(data["Process Name"][i]).lower()
                operation = str(data["Operation"][i]).lower()
                integrity = str(data["Integrity"][i]).lower()

                if (
                    proc_name not in bad_process_names
                    and operation not in bad_operation_names
                ):

                    if (".exe" not in orig_path and ".dll" not in orig_path):
                        # Cleanup Registry Key Path
                        dir_count = len(re.findall(r"\\", orig_path))
                        path = orig_path.split("\\")
                        clean_path = ""

                        for j in range(0, dir_count):
                            if j == (dir_count - 1):
                                clean_path += path[j]
                            elif j == 0:
                                clean_path += path[j] + ":\\"
                            else:
                                clean_path += path[j] + "\\"
                    else:
                        # Send the .DLL/.EXE to be analyzed.
                        clean_path = orig_path
                        # Avoid issues with rundll32.exe
                        if ("rundll32.exe c:" in path):
                          clean_path = clean_path.split("rundll32.exe ")[1]

                        # Avoid Issues with CLI arguments:
                        if (".exe -" in clean_path):
                            clean_path = clean_path.split(" -")[0]
                            
                        base_path = os.path.dirname(clean_path)

                    # Make sure this is not a duplicate key before saving
                    if clean_path not in previous_paths:
                        # Save key to cleaned keys
                        final_data = f"\"{proc_name}\",\"{orig_path}\",\"{clean_path}\",\"{operation}\",\"{integrity}\""
                        cleaned_data_file.write(final_data + "\n")
                        previous_paths.add(clean_path)

                    if ((".exe" in clean_path.lower() or ".dll" in clean_path.lower()) and base_path not in previous_paths):
                        final_data = f"\"{proc_name}\",\"{orig_path}\",\"{base_path}\",\"{operation}\",\"{integrity}\""
                        cleaned_data_file.write(final_data + "\n")
                        previous_paths.add(base_path)

                    pbar.update(1)

                else:
                    pbar.update(1)

            pbar.close()
            cleaned_data_file.close()

        except Exception as e:
            self.__print_exception()

    # ===============================================#
    # Purpose: Thread the win32api DACL lookups     #
    # Return: None                                  #
    # ===============================================#
    ## build_command_list --> __thread_commands --> __get_acl_list --> __write_acl
    def build_command_list_procmon(self, total_threads):
        try:
             # DataFrame Objects
            data = pd.read_csv(f"{self.__output_dir}/cleaned_paths.csv", encoding = "ISO-8859-1")
            headers = list(data)
            total_number_of_paths = data.shape[0]

            commands = [None] * total_threads
            commands_index = 0
            total_commands_sent = 0

            pbar = tqdm(total=total_number_of_paths)
            pbar.set_description("Analyzing ACL's")

            for i in range(0, total_number_of_paths):
                
                #cleaned_data_file.write("Process Name,Original Path,Clean Path,Operation,Integrity")
                proc_name = str(data["Process Name"][i]).lower()
                orig_cmd = str(data["Original Path"][i]).lower()
                clean_cmd = str(data["Clean Path"][i]).lower()
                operation = str(data["Operation"][i]).lower()
                integrity = str(data["Integrity"][i]).lower()

                # Generate a Dictionary that will be stored in a list (I know, it's messy...)
                cmd = {
                    "proc_name" : proc_name, 
                    "orig_cmd"  : orig_cmd, 
                    "clean_cmd" : clean_cmd,
                    "operation" : operation,
                    "integrity" : integrity
                    }

                # if the index is less than the requested threads, keep adding commands to the list
                if commands_index < total_threads:
                    commands[commands_index] = cmd
                    commands_index += 1
                    total_commands_sent += 1

                # If commands list is full, send it off for analysis and reset
                if commands_index == total_threads:
                    self.__thread_commands(commands, "procmon")  # Send the data
                    commands = [None] * total_threads  # Reset list and counter
                    commands_index = 0
                    commands[commands_index] = cmd  # Add current path to [0] place in list
                    commands_index += 1
                    total_commands_sent += 1

                pbar.update(1)

            # Send the last set of commands:
            self.__thread_commands(commands, "procmon")
            pbar.close()
            return total_number_of_paths

        except Exception as e:
            self.__print_exception()



    # ===============================================#
    # Purpose: Thread the win32api DACL lookups     #
    # Return: None                                  #
    # ===============================================#
    ## build_command_list --> __thread_commands --> __get_acl_list --> __write_acl
    def build_command_list_path(self, total_threads, path):
        try:

            file_paths = []
            
            # We need to disable the file system redirects before enumerating any 
            # privileged paths such as C:\Windows\System32. 
            with windows_objects.disable_file_system_redirection():
                for root, dirs, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        file_paths.append(full_path)

            total_number_of_paths = len(file_paths)
            commands = [None] * total_threads
            commands_index = 0
            total_commands_sent = 0

            pbar = tqdm(total=total_number_of_paths)
            pbar.set_description("Analyzing ACL's")

            for i, f_path in enumerate(file_paths):
                
                cmd = f_path.strip()

                # if the index is less than the requested threads, keep adding commands to the list
                if commands_index < total_threads:
                    commands[commands_index] = cmd
                    commands_index += 1
                    total_commands_sent += 1

                # If commands list is full, send it off for analysis and reset
                if commands_index == total_threads:
                    self.__thread_commands(commands, "path")  # Send the data
                    commands = [None] * total_threads  # Reset list and counter
                    commands_index = 0
                    commands[commands_index] = cmd  # Add current path to [0] place in list
                    commands_index += 1
                    total_commands_sent += 1

                pbar.update(1)

            # Send the last set of commands:
            self.__thread_commands(commands, "path")
            pbar.close()
            return total_number_of_paths

        except Exception as e:
            self.__print_exception()

    # ===============================================#
    # Purpose: Thread the win32api DACL lookups     #
    # Return: None                                  #
    # ===============================================#
    def __thread_commands(self, commands, analysis_type):
        try:
            threads = []
            tot_commands = len(commands)

            if (analysis_type == "procmon"):
                for i in range(tot_commands):

                    # Analyze registry keys
                    if "hklm:" in str(commands[i]).lower():
                        t = threading.Thread(
                            target=self.__reg_enum.get_acl_list_procmon, args=(commands[i],)
                        )
                        t.daemon = True
                        t.start()
                        threads.append(t)
                        t.join()
                    # Disregard NONE type objects
                    elif commands[i] == None:
                        pass
                    # Analyze File Paths
                    else:
                        t = threading.Thread(
                            target=self.__file_enum.get_acl_list_procmon, args=(commands[i],)
                        )
                        t.daemon = True
                        t.start()
                        threads.append(t)
                        t.join()
            
            if (analysis_type == "path"):
                for i in range(tot_commands):
                    
                    if (commands[i] == None):
                        pass
                    else:
                        t = threading.Thread(
                            target=self.__file_enum.get_acl_list_path, args=(commands[i],)
                        )
                        t.daemon = True
                        t.start()
                        threads.append(t)

                        if (i == (tot_commands -1)):
                            t.join()


        except Exception as e:
            self.__print_exception()

    # ===============================================#
    # Purpose:Check for suspect permission sets     #
    # Return: Boolean                               #
    #   - True: Found suspect Permission            #
    #   - False: benign                             #
    # ===============================================#
    def __check_permission(self, line):
        try:

            tmp = False
            users = [self.__username, "users", "everyone", "interactive", "authenticated"]
            permissions = [
                "fullcontrol",
                "write",
                "changepermissions",
                "takeownership",
                "traverse",
                "key_write",
                "generic_write",
                "key_all_access",
                "file_all_access",
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

    # ===============================================#
    # Purpose: analyzes the filepaths or registry   #
    # class looking for abusable permissions        #
    #                                               #
    # Return: int - # of suspect permissions        #
    # ===============================================#
    def analyze_acls(self):
        try:
            df = pd.DataFrame(columns=["Process_Name", "Integrity", "Operation", "Accessed Object", "ACLs"])
            num_lines = sum(1 for line in open(f"{self.__output_dir}/raw_acls.txt"))

            with open(f"{self.__output_dir}/raw_acls.txt", "r") as f:

                permission_index = 0  # Index of determining number of permissions between Access and Audit
                total_index = 0  # Index of all frames we have built
                fun_index = 0  # Index of Full_Control Registry Keys
                add = False  # Placeholder to determine if user has full permissions

                proc_name = ""      # Placeholder for process name
                integrity = ""      # Placeholder for process integrity
                operation = ""      # Placeholder for operation type
                orig_cmd = ""       # Placeholder for original command/path
                clean_cmd = ""      # Placeholder for cleaned command/path
                access = ""         # Placeholder for access control list

                pbar = tqdm(total=num_lines)
                pbar.set_description("Looking for Evil")

                for line in f:
                    line = line.lower()
                    try:

                        if "process_name" in line:
                            proc_name = str(line.split(": ")[1]).strip()

                        if "integrity" in line:
                            integrity = str(line.split(": ")[1]).strip()

                        if "operation" in line:
                            operation = str(line.split(": ")[1]).strip()

                        if "original_cmd" in line:
                            orig_cmd = str(line.split(": ")[1]).strip()
                        
                        if "path" in line:
                            clean_cmd = str(line.split(": ")[1]).strip()
                        
                        # Determine Access
                        if (
                            permission_index >= 1
                            and "--------end--------" not in line
                        ):
                            access += "\n" + str(line).strip()
                            permission_index += 1
                            user_full_control = self.__check_permission(line)
                            if user_full_control:
                                add = True

                        if (
                            "access:" in line
                        ):  # Check if we are at the ACCESS portion:
                            access += line.split("access:")[1].strip()
                            permission_index += 1  # Denote which permission we are at
                            user_full_control = self.__check_permission(line)
                            if user_full_control:
                                add = True

                        if "--------end--------" in line:

                            if add:
                                final_data = {
                                    "Process_Name": proc_name, 
                                    "Integrity": integrity,
                                    "Operation": operation,
                                    "Accessed Object": clean_cmd,
                                    "ACLs": access
                                    }
                                df = df.append(final_data, ignore_index=True)
                                fun_index += 1

                            path = None
                            owner = None
                            group = None
                            add = False
                            permission_index = 0
                            total_index += 1
                            access = ""

                        pbar.update(1)

                    except Exception as e:
                        pbar.update(1)
                        pass

                pbar.close()

            df.to_excel(self.__final_report)
            return fun_index

        except Exception as e:
            self.__print_exception()

    # ===============================================#
    # Purpose: Given a file of DACLs, this function #
    # analyzes the filepaths or registry class      #
    # looking for abusable permissions              #
    #                                               #
    # Return: int - # of suspect permissions        #
    # ===============================================#
    def analyze_acls_from_file(self, file):
        try:
            df = pd.DataFrame(columns=["Process_Name", "Integrity", "Operation", "Accessed Object", "ACLs"])
            num_lines = sum(1 for line in open(file))

            with open(file, "r") as f:

                permission_index = 0  # Index of determining number of permissions between Access and Audit
                total_index = 0  # Index of all frames we have built
                fun_index = 0  # Index of Full_Control Registry Keys
                add = False  # Placeholder to determine if user has full permissions

                proc_name = ""      # Placeholder for process name
                integrity = ""      # Placeholder for process integrity
                operation = ""      # Placeholder for operation type
                orig_cmd = ""       # Placeholder for original command/path
                clean_cmd = ""      # Placeholder for cleaned command/path
                access = ""         # Placeholder for access control list

                pbar = tqdm(total=num_lines)
                pbar.set_description("Looking for Evil")

                for line in f:
                    line = line.lower()
                    try:

                        if "process_name" in line:
                            proc_name = str(line.split(": ")[1]).strip()

                        if "integrity" in line:
                            integrity = str(line.split(": ")[1]).strip()

                        if "operation" in line:
                            operation = str(line.split(": ")[1]).strip()

                        if "original_cmd" in line:
                            orig_cmd = str(line.split(": ")[1]).strip()
                        
                        if "path" in line:
                            clean_cmd = str(line.split(": ")[1]).strip()

                        # Determine Access
                        if (
                            permission_index >= 1
                            and "--------end--------" not in line
                        ):
                            access += "\n" + str(line).strip()
                            permission_index += 1
                            user_full_control = self.__check_permission(line)
                            if user_full_control:
                                add = True

                        if (
                            "access:" in line
                        ):  # Check if we are at the ACCESS portion:
                            access += line.split("access:")[1].strip()
                            permission_index += 1  # Denote which permission we are at
                            user_full_control = self.__check_permission(line)
                            if user_full_control:
                                add = True

                        if "--------end--------" in line:

                            if add:
                                final_data = {
                                    "Process_Name": proc_name, 
                                    "Integrity": integrity,
                                    "Operation": operation,
                                    "Accessed Object": clean_cmd,
                                    "ACLs": access
                                    }
                                df = df.append(final_data, ignore_index=True)
                                fun_index += 1

                            path = None
                            owner = None
                            group = None
                            add = False
                            permission_index = 0
                            total_index += 1
                            access = ""

                        pbar.update(1)

                    except Exception as e:
                        pass
                        pbar.update(1)
                pbar.close()

            df.to_excel(self.__final_report)
            return fun_index

        except Exception as e:
            self.__print_exception()

    # ===============================================#
    # Purpose: Clean Exception Printing              #
    # Return: None                                   #
    # ===============================================#
    def __print_exception(self):
        exc_type, exc_obj, tb = sys.exc_info()
        tmp_file = tb.tb_frame
        lineno = tb.tb_lineno
        filename = tmp_file.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, tmp_file.f_globals)
        print(f"{Fore.RED}EXCEPTION IN: {Fore.GREEN}{filename}\n\t[i] LINE: {lineno}, {line.strip()}\n\t[i] OBJECT: {exc_obj}{Fore.RESET}")

    # ===============================================#
    # Purpose: return Total amount of errors seen    #
    # Return: int                                    #
    # ===============================================#
    def get_error_count(self):
      try:
        file_errors = self.__file_enum.error_index
        reg_errors = self.__reg_enum.error_index
        return (file_errors + reg_errors)
      except:
        self.__print_exception()
