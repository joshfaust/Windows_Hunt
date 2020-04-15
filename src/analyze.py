import os
import re
import io
import sys
import time
import getpass
import hashlib
import threading
import linecache
import pandas as pd
import concurrent.futures
from . import permissions, windows_objects
from tqdm import tqdm
from colorama import Fore, init

init()

# --------------------------------------------------#
# Name:     Analysis Class                          #
# Purpose:  Conduct the overall DACL analysis       #
# Author:   @jfaust0                                #
# Website:  sevrosecurity.com                       #
# --------------------------------------------------#


class analyze:

    # o_dir = output directory
    # initialize = do you want to initialize all write objects
    def __init__(self, o_dir):
        self.name = "Analysis"
        self.__procmon_analysis = []        # A list of dictionaries
        self.__path_analysis = []
        self.__output_dir = o_dir
        self.__final_report = f"{self.__output_dir}/evil.xlsx"
        self.__permission_enum = permissions.permissions(self.__output_dir)
        self.__username = str(getpass.getuser()).lower()

    # ==========================================================#
    # Purpose:  loads raw procmon csv output into a Pandas      #
    #           dataframe, removed duplicates, and outputs all  #
    #           cleaned / de-duplicated objects to              #
    #           cleaned_paths.txt                               #
    # Return:   Pandas Dataframe                                #
    # ==========================================================#
    def parse_procmon_csv(self, p_file):
        try:
            # Names we do not want to enumerate
            bad_process_names = [
                "conhost.exe",
                "dem.exe",
                "svchost.exe",
                "procmon64.exe"
            ]  
            # Operations we don't care about
            bad_operation_names = [
                "regclosekey",
                "regqueryvalue",
                "regenumvalue",
                "regquerykeysecurity",
                "regquerykey",
            ] 

            # Dataframe to hold the parsed procmon data:
            output_dataframe = pd.DataFrame(columns=["process_name", "orig_path", "clean_path", "operation", "integrity"])

            input_dataframe = pd.read_csv(p_file)       # Read Procmon.CSV data into dataframe
            dataframe_length = input_dataframe.shape[0] # Size of procmon dataframe
            deduplication = (set())                     # holds hashes of previously added paths to avoid duplication
            path = ""                                   # placeholder for original paths (not cleaned)
            pbar = tqdm(total=dataframe_length)         # Progress Bar
            pbar.set_description("Analyzing Procmon Data")

            for i in range(0, dataframe_length):
                
                # Pull in dataframe content we're interested in.
                orig_path = str(input_dataframe["Path"][i]).lower()
                proc_name = str(input_dataframe["Process Name"][i]).lower()
                operation = str(input_dataframe["Operation"][i]).lower()
                integrity = str(input_dataframe["Integrity"][i]).lower()

                if (proc_name not in bad_process_names
                    and operation not in bad_operation_names):

                    # If path is a registry key:
                    if (".exe" not in orig_path and ".dll" not in orig_path and "c:" not in orig_path):
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

                    # If path is an executable or library:
                    else:
                        clean_path = orig_path

                        # Avoid issues with rundll32.exe
                        if ("rundll32.exe c:" in path):
                          clean_path = clean_path.split("rundll32.exe ")[1]

                        # Avoid Issues with CLI arguments:
                        if (".exe -" in clean_path):
                            clean_path = clean_path.split(" -")[0]

                        base_path = os.path.dirname(clean_path)

                    clean_hash = hashlib.md5(clean_path.encode("utf-8")).hexdigest()    # MD5 of the Cleaned Path
                    base_hash = hashlib.md5(base_path.encode("utf-8")).hexdigest()      # MD5 of the Base Path

                    # Make sure this is not a duplicate key before saving
                    if clean_hash not in deduplication and len(clean_path) > 4:
                        # Save the Cleaned path (Full Path) to the dataframe
                        final_data = {
                            "process_name": proc_name, 
                            "orig_path": orig_path, 
                            "clean_path": clean_path, 
                            "operation": operation,
                            "integrity": integrity
                            }
                        output_dataframe = output_dataframe.append(final_data, ignore_index=True)
                        deduplication.add(clean_hash)

                    # Save the Base Path (no file included) to the dataframe
                    if ((".exe" in clean_path.lower() or ".dll" in clean_path.lower()) and base_hash not in deduplication and len(clean_path) > 4):
                        final_data = {
                            "process_name": proc_name, 
                            "orig_path": orig_path, 
                            "clean_path": base_hash, 
                            "operation": operation,
                            "integrity": integrity
                            }
                        output_dataframe = output_dataframe.append(final_data, ignore_index=True)
                        deduplication.add(base_hash)

                    pbar.update(1)

                else:
                    pbar.update(1)

            pbar.close()
            return output_dataframe

        except Exception as e:
            self.__print_exception()

    # ==========================================================#
    # Purpose: Thread the win32api DACL lookups                 #
    # Return: None                                              #
    # ==========================================================#
    ## build_command_list --> __thread_commands --> __get_acl_list --> __write_acl
    def build_command_list_procmon(self, total_threads, df):
        try:
            # DataFrame Objects
            total_number_of_paths = df.shape[0]

            commands = [None] * total_threads
            commands_index = 0
            total_commands_sent = 0

            pbar = tqdm(total=total_number_of_paths)
            pbar.set_description("Analyzing ACL's")

            for i in range(0, total_number_of_paths):
                
                #cleaned_data_file.write("Process Name,Original Path,Clean Path,Operation,Integrity")
                proc_name = str(df["process_name"][i]).lower()
                orig_cmd = str(df["orig_path"][i]).lower()
                clean_cmd = str(df["clean_path"][i]).lower()
                operation = str(df["operation"][i]).lower()
                integrity = str(df["integrity"][i]).lower()

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



    # ==========================================================#
    # Purpose: Thread the win32api DACL lookups                 #
    # Return: None                                              #
    # ==========================================================#
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

    # ==============================================#
    # Purpose:  Thread the win32api DACL lookups    #
    # Return:   Adds dictionaries to class list     #
    # ==============================================#
    def __thread_commands(self, commands, analysis_type):
        try:
            threads = []
            tot_commands = len(commands)
            pool = tot_commands

            if (analysis_type == "procmon"):
                with concurrent.futures.ThreadPoolExecutor(max_workers=tot_commands) as executor:
                    for i in range(tot_commands):

                        # Analyze registry keys
                        if "hklm:" in str(commands[i]).lower() or "hkcu:" in str(commands[i]).lower():
                            t = executor.submit(self.__permission_enum.get_registry_key_acl_procmon, commands[i])
                            self.__procmon_analysis.append(t.result())

                        # Disregard NONE type objects
                        elif commands[i] == None:
                            pass

                        # Analyze File Paths
                        else:
                            t = executor.submit(self.__permission_enum.get_file_path_acl_procmon, commands[i])
                            self.__procmon_analysis.append(t.result())

            if (analysis_type == "path"):
                with concurrent.futures.ThreadPoolExecutor(max_workers=tot_commands) as executor:
                    for i in range(tot_commands):
                        
                        # Analyse File Paths
                        if (commands[i] != None):
                            t = executor.submit(self.__permission_enum.get_file_path_acl, commands[i])
                            self.__path_analysis.append(t.result())

        except Exception as e:
            self.__print_exception()

    # ==============================================#
    # Purpose:Check for suspect permission sets     #
    # Return: Boolean                               #
    #   - True: Found suspect Permission            #
    #   - False: benign                             #
    # ==============================================#
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
                "service_change_config"
                "changepermissions",
                "takeownership",
                "traverse",
                "key_all_access",
                "file_all_access"
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

    # ==========================================================#
    # Purpose:  Reviews all the dictionary objects stored in    #
    #           __procmon_analysis. This function is dedicated  #
    #           to reviewing only the procmon data to determine #
    #           if weak/bad permissions are resident on objects #
    #           that may be use to elevate privileges. After    #
    #           the full analysis, a final report is written to #
    #           disk detailed all objects that a user has       #
    #           control                                         #
    #           over.                                           #
    # Return: int - number of weak permissions found            #
    # ==========================================================#
    def analyze_acls_procmon(self):
        try:

            # __procmon_analysis Dictionary Format:
            '''
            acl_dict = {
                "process_name": path_dict["proc_name"],
                "integrity": path_dict["integrity"],
                "operation": path_dict["operation"],
                "original_cmd": path_dict["orig_cmd"],
                "path": r_path,
                "acls": acls
                }
            '''
            df = pd.DataFrame(columns=["Process_Name", "Integrity", "Operation", "Accessed Object", "ACLs"])
            pbar = tqdm(total=len(self.__procmon_analysis))
            pbar.set_description("Looking for Evil")
            add_index = 0

            for obj in self.__procmon_analysis:
                add = False
                acl_dict = dict(obj)

                if (len(acl_dict) > 3):                         # Error Dicts and < 3, skip those
                    proc_name = acl_dict["process_name"]        # Placeholder for process name
                    integrity = acl_dict["integrity"]           # Placeholder for process integrity
                    operation = acl_dict["operation"]           # Placeholder for operation type
                    orig_cmd = acl_dict["original_cmd"]         # Placeholder for original command/path
                    clean_cmd = acl_dict["path"]                # Placeholder for cleaned command/path
                    access = acl_dict["acls"]                   # Placeholder for access control list
                    
                    parsed_access = access.split("\n")           # Split each individual ACL via newline
                    for line in parsed_access:
                        if (user_full_control := self.__check_permission(line)):
                            add = user_full_control
                            break;

                    if add:
                        final_data = {
                            "Process_Name": proc_name, 
                            "Integrity": integrity,
                            "Operation": operation,
                            "Accessed Object": clean_cmd,
                            "ACLs": access
                            }
                        df = df.append(final_data, ignore_index=True)
                        add_index += 1

                    add = False
                    access = ""
                pbar.update(1)

            pbar.close()
            df.to_excel(self.__final_report)
            return add_index

        except Exception as e:
            print(f"\n\n{obj}")
            self.__print_exception()


    # ==========================================================#
    # Purpose:  Used during the (-f, --files) flagwhich,        # 
    #           analyzes all files given a  starting path. ACLs #
    #           are pulled for each path/file and saved to the  #
    #           class variable __path_analysis. This function   #
    #           uses the __path_analysis variable to enumerate  #
    #           weak/bad permissions on a file-by-file basis and#
    #           saves the output to an excel document           #  
    #                                                           #
    # Return: Integer - count of all weak permissions found     #
    # ==========================================================#
    def analyze_acls_path(self):
        try:
            output_df = pd.DataFrame(columns=["Path", "Permissions"])
            add_index = 0

            for obj in self.__path_analysis:        # For each dictionary in __path_analysis
                acls = ""                           # Placeholder for ACL's string
                add = False                         # Dictate if bad permission we found
                acl_dict = dict(obj)                # Typecast into a dict() object

                if (acl_dict["error"] == None):     # If the ACL enumeration contained no errors
                    parsed_access = acl_dict["acls"]
                    
                    for line in parsed_access:      # Check each ACL line for weak permissions
                        if (user_full_control := self.__check_permission(line)):
                            add = user_full_control
                            break;
                    
                    if add:
                        for line in parsed_access:
                            acls += line + "\n"

                        final_data = {
                            "Path": acl_dict["file_path"],
                            "Permissions": acls
                        }
                        output_df = output_df.append(final_data, ignore_index=True)
                        add_index += 1

            output_df.to_excel(f"{self.__output_dir}/weak_path_permissions.xlsx")
            return add_index

        except Exception as e:
            self.__print_exception()


    # ==========================================================#
    # Purpose:  Given a list of ACL's, enumerate each ACL to    # 
    #           check for weak/bad permission on the file in    #
    #           question. If the ACL's are weak, return a bool  #
    #                                                           #
    # Return:   Boolean                                         #
    # ==========================================================#
    def analyze_acls_from_list(self, acl_list):
        try:
            add = False  # Placeholder to determine if user has full permissions

            for line in acl_list:
                line = line.lower()

                if (user_full_control := self.__check_permission(line)):
                    add = user_full_control
                    break;

            return add

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
        file_errors = self.__permission_enum.error_index
        return file_errors
      except:
        self.__print_exception()
