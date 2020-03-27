import re
import os
import sys
import getpass
import datetime
import linecache
import win32service
import win32com.client
import pandas as pd
from winreg import *
from tqdm import tqdm
from bs4 import BeautifulSoup
from colorama import Fore, init
from . import windows_objects, filepaths, analyze, registry
init()

# --------------------------------------------------#
# Name:     Low Hanging Fruit Class                 #
# Purpose:  Conduct the overall DACL analysis       #
# Author:   @jfaust0                                #
# Website:  sevrosecurity.com                       #
# --------------------------------------------------#


class low_haning_fruit:

    def __init__(self, o_dir):
        self.name = "Low Hangning Fruit"
        self.__output_dir = o_dir
        self.__windows_objects = windows_objects.windows_services_and_tasks()
        self.__windows_file_path = re.compile(r"^([A-Za-z]):\\((?:[A-Za-z\d][A-Za-z\d\- \x27_\(\)~]{0,61}\\?)*[A-Za-z\d][A-Za-z\d\- \x27_\(\)]{0,61})(\.[A-Za-z\d]{1,6})?")
        self.__password_regex = re.compile(r"(?i)(adminpassword|password|pass|login|creds)( |)(=|:).*")
        self.__username = str(getpass.getuser()).lower()
        self.__reg_handle = None
        self.__key_handle = None
        self.__sub_key_handle = None


    def registry_analysis(self):
        try:
            df = pd.DataFrame(columns=["Root_Key_Name", "Root_Key_Values", "Sub_Keys", "Sub_Key_Values", "ACLS"])
            r = registry.registry_enumeration(self.__output_dir, False)
            
            registry_keys = [
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\Winlogon",
                "HKCU\\Software\\ORL\\WinVNC3\\Password",
                "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions",
                "HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP",
                "HKLM\\Software\\RealVNC\\WinVNC4",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated",
                "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated"
                ]
            wanted_key_names = [
                "defaultusername",
                "defaultdomainname",
                "defaultpassword",
                "password",
                "pass",
                "credentials",
                "user",
                "username",
                "privatekeyfile",
                "hostname",
                "shell"
                ]
            
            pbar = tqdm(total=len(registry_keys))
            pbar.set_description("Analyzing Registry Keys")
            for root_key in registry_keys:

                sub_key_names = []
                tmp_value_holder = []   # Hold all the interesting keys in a single dict
                root_key_values = {}
                sub_key_values = {}
                key_exists = False

                # Open a handle to the correct registry path
                if ("hkcu" in root_key.lower()):
                    key = root_key.split("HKCU\\")[1]
                    self.__reg_handle = ConnectRegistry(None, HKEY_CURRENT_USER)

                elif ("hklm" in root_key.lower()):
                    key = root_key.split("HKLM\\")[1]
                    self.__reg_handle = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
                
                try:
                    # Open a key:
                    self.__key_handle = OpenKey(self.__reg_handle, key)
                    key_exists = True
                except:
                    pbar.update(1)
                    continue
                
                # Obtain information about the root key:
                total_sub_keys, total_key_values, last_modified_date = QueryInfoKey(self.__key_handle)
                last_modified_date = self.__ldap_to_datetime(last_modified_date)
                
                # Enumerate root key values:
                if (total_key_values != 0):
                    for i in range(total_key_values):
                        kv = EnumValue(self.__key_handle, i)
                        value_name = list(kv)[0]

                        if (value_name.lower() in wanted_key_names):        # Only add keys that match our wanted_key_names[]
                            root_key_values[value_name] = kv

                # Enumerate sub_key names:
                if (total_sub_keys != 0):
                    for i in range(total_sub_keys):
                        sub_key_name = EnumKey(self.__key_handle, i)
                        sub_key_names.append(sub_key_name)

                # Enumerate sub_key_values:
                if (len(sub_key_names) != 0):
                    # For each sub_key, open a handle:
                    for _sub_key_name in sub_key_names:
                        self.__sub_key_handle = OpenKey(self.__key_handle, _sub_key_name)
                        _total_sub_keys, _total_key_values, _last_modified_date = QueryInfoKey(self.__sub_key_handle)
                        
                        if (_total_key_values != 0):

                            for j in range(_total_key_values):
                                _kv = EnumValue(self.__sub_key_handle, j)   # Key Value
                                _value_name = list(_kv)[0]                  # Value Name

                                if (_value_name.lower() in wanted_key_names):
                                    tmp_value_holder.append(_kv)

                        sub_key_values[_sub_key_name] = tmp_value_holder    # add a dict object to another dict object (dict inception?)
                        tmp_value_holder = []                               # Clear out the value holder array for the next interation. 
                        CloseKey(self.__sub_key_handle)                     # Close the sub_key handle

                if (key_exists):
                    final_data = {
                        "Root_Key_Name": root_key.strip(),
                        "Root_Key_Values": root_key_values, 
                        "Sub_Keys": sub_key_names,
                        "Sub_Key_Values": sub_key_values,
                        "ACLS": r.get_acl_list_return(root_key)
                        }

                    df = df.append(final_data, ignore_index=True)

                # Cleanup
                CloseKey(self.__key_handle)
                CloseKey(self.__reg_handle)
                pbar.update(1)
                
            CloseKey(self.__sub_key_handle)

            return {"dataframe": df, }

        except Exception as e:
            self.__print_exception()


    # ======================================================#
    # Purpose: Looks through the filesystem examining known #
    # files that contain passwords/credentials as well as   #
    # dynamically assessing if a file is worth              #
    # investigating further based on filename/type          #
    #                                                       #
    # Return: dict - contains number of issues found        #
    # ======================================================#
    def look_for_credentials(self):
        try:
            # Output File
            out_file = open(f"{self.__output_dir}/credential_enumeration.txt", "a+")

            # Function Variables
            found_cred_files = 0            # counter of files that have credentials/passwords within. (dictated by regex)
            found_known_cred_files = []     # Holds all found files that match with known_cred_files[]
            interesting_file_paths = []     # Holds all interesting files the deem further analysis

            interesting_file_types = [
                ".ini", 
                ".xml", 
                ".conf", 
                ".config", 
                ".inf",
                ".txt"
                ]
            known_cred_files = [
                "sysprep.inf",
                "sysprep.xml",
                "unattended.xml",
                "unattend.xml",
                "services.xml",
                "scheduledtasks.xml",
                "printers.xml",
                "drives.xml",
                "datasources.xml",
                "groups.xml"
                ]
            exclusion_list = [
                "credential_enumeration.txt"
                ]

            # We need to disable the file system redirects before enumerating any 
            # privileged paths such as C:\Windows\System32. 
            print("\n[i] Enumerating all system files. Please Wait.")
            with windows_objects.disable_file_system_redirection():
                for root, dirs, files in os.walk("C:\\"):
                    for file in files:
                        if (file.endswith(tuple(interesting_file_types)) 
                        and file.lower() not in known_cred_files
                        and file.lower() not in exclusion_list):

                            full_path = os.path.join(root, file)
                            interesting_file_paths.append(full_path)
                        
                        if (file.lower() in known_cred_files
                        and file.lower() not in exclusion_list):

                            full_path = os.path.join(root, file)
                            found_known_cred_files.append(full_path)


            # Analyze the found_known_cred_files list 
            pbar = tqdm(total=len(found_known_cred_files))
            pbar.set_description("Analyzing Known Credential Files")
            for file_path in found_known_cred_files:
                added = False
                try:
                    # For each line in a singular file, check it against the regex
                    # to determine if passwords/credentials present.
                    for i, line in enumerate(open(file_path, encoding="utf-8")):
                        creds = re.search(self.__password_regex, line)
                        if (creds != None):

                            if (not added):
                                out_file.write(f"FILE:{' ' * 4}{file_path}\n")
                                added = True
                                found_cred_files += 1

                            out_file.write(f"CREDS:{' ' * 3}{str(creds.group())[0:100]}\n")

                except Exception as e:
                    pass

                if (added):
                    out_file.write("-"*100 + "\n")

                pbar.update(1)
            pbar.close()
            
            # Analyze files that met the interesting file type criteria
            pbar = tqdm(total=len(interesting_file_paths))
            pbar.set_description("Analyzing Possible Credential Files")
            for file_path in interesting_file_paths:
                added = False
                try:
                    # For each line in a singular file, check it against the regex
                    # to determine if passwords/credentials present.
                    for i, line in enumerate(open(file_path, encoding="utf-8")):
                        creds = re.search(self.__password_regex, line)
                        if (creds != None):

                            if (not added):
                                out_file.write(f"FILE:{' ' * 4}{file_path}\n")
                                added = True
                                found_cred_files += 1

                            out_file.write(f"CREDS:{' ' * 3}{str(creds.group())[0:100]}\n")

                except Exception as e:
                    pass
                
                if (added):
                    out_file.write("-"*100 + "\n")

                pbar.update(1)
            pbar.close()

            return {"total_cred_files": found_cred_files}

        except Exception as e:
            self.__print_exception()

    # ======================================================#
    # Purpose: Enumerates all scheduled tasks and looks     #
    # for open / liberal ACL permissions to the command.    #
    #                                                       #
    # Return: dict - contains number of issues found        #
    # ======================================================#
    def analyze_scheduled_tasks(self):

        """
        # Enumeration of the COM Object via powershell:
            --> $o = [activator]::CreateInstance([type]::GetTypeFromProgID('Schedule.Service'))
            --> $o.Connect() | Get-Member
            --> $f = $o.GetFolder("")
            --> $t = $f.GetTasks(0)
            --> $t | Get-Member
        
        Name                  MemberType Definition
        ----                  ---------- ----------
        GetInstances          Method     IRunningTaskCollection GetInstances (int)
        GetSecurityDescriptor Method     string GetSecurityDescriptor (int)
        Run                   Method     IRunningTask Run (Variant)
        RunEx                 Method     IRunningTask RunEx (Variant, int, int, string)
        SetSecurityDescriptor Method     void SetSecurityDescriptor (string, int)
        Stop                  Method     void Stop (int)
        Definition            Property   ITaskDefinition Definition () {get}
        Enabled               Property   bool Enabled () {get} {set}
        LastRunTime           Property   Date LastRunTime () {get}
        LastTaskResult        Property   int LastTaskResult () {get}
        Name                  Property   string Name () {get}
        NextRunTime           Property   Date NextRunTime () {get}
        NumberOfMissedRuns    Property   int NumberOfMissedRuns () {get}
        Path                  Property   string Path () {get}
        State                 Property   _TASK_STATE State () {get}
        Xml                   Property   string Xml () {get}
        """

        try:
            # Function Variables / Objects
            out_file = open(f"{self.__output_dir}/scheduled_tasks_enumeration.txt", "a+")
            total_tasks = 0
            vuln_perms = 0
            acl_list = []
            vuln_tasks = []
            task_path = ""
            task_name = ""
            task_state = ""
            last_run = ""
            last_result = ""
            next_run = ""

            # Class Objects
            fp = filepaths.filepath_enumeration(self.__output_dir, False)
            an = analyze.analyze(self.__output_dir, False)

            # Windows Schedule.Service COM Object initialization
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            folders = [scheduler.GetFolder("\\")]

            # Get the total number of tasks to enumerate:
            while folders:
                folder = folders.pop(0)
                folders += list(folder.GetFolders(0))
                for t in folder.GetTasks(0):
                    total_tasks += 1

            pbar = tqdm(total=total_tasks)
            pbar.set_description("Analyzing Scheduled Tasks")
            
            # Enumerate each task individually
            folders = [scheduler.GetFolder("\\")]
            while folders:

                folder = folders.pop(0)
                folders += list(folder.GetFolders(0))

                for task in folder.GetTasks(0):
                    acls = ""
                    task_path = task.Path
                    task_name = task.Name
                    task_state = self.__windows_objects.TASK_STATE[task.State]
                    last_run = task.LastRunTime
                    last_result = task.LastTaskResult
                    next_run = task.NextRunTime

                    # We have to pull the XML object to obtain the command/executable
                    # that is scheduled to run. This has issues where at times, there
                    # is not command object.
                    try:
                        xml_data = BeautifulSoup(task.Xml, "xml")
                        raw_task_command = xml_data.find("Command").text
                        task_command = str(raw_task_command).replace('"', "").strip()

                        # Handle ENV VAR paths
                        if "%" in task_command:
                            env_key = re.search(r"\%(\w+)\%", task_command)
                            raw_key = str(env_key.group(1)).lower()
                            replace_key = env_key.group(0)
                            replacement = os.environ.get(raw_key)
                            task_command = task_command.replace(replace_key, replacement)

                    except Exception as e:
                        task_command = "Unknown"

                    # Within the XML, there is an Arguments parameter. This is something
                    # we parse for further analysis. (i.e., look for other exe/dll objects)
                    try:
                        task_args = xml_data.find("Arguments").text
                    except:
                        task_args = "None"

                    # If the Command is not Unknown, obtain its ACL's for further analysis.
                    if task_command != "Unknown":
                        acl_list = fp.get_acl_list_return(task_command)

                        for i, acl in enumerate(acl_list):

                            if i == 0:
                                spacing = " " * 12
                            else:
                                spacing = " " * 17

                            if i == (len(acl_list) - 1):
                                acls += f"{spacing}{acl}"
                            else:
                                acls += f"{spacing}{acl}\n"

                    # Analyze the Commands ACL values for access rights issues / vulns.
                    suspect_task = an.analyze_acls_from_list(acl_list)
                    if suspect_task:
                        vuln_perms += 1
                        if (task_name not in vuln_tasks):
                            vuln_tasks.append(task_name)

                    data = f"""
Task Name:{" "*7}{task_name}
Task Command:{" "*4}{task_command}
Command Args:{" "*4}{task_args}
Task Path:{" "*7}{task_path}
Task State:{" "*6}{task_state}
Last Run:{" "*8}{last_run}
Next Run:{" "*8}{next_run}
ACLS:{acls}
Suspect Perms:{" "*3}{suspect_task}
          """
                    out_file.write(data)
                    pbar.update(1)

            return {
                "total_tasks": total_tasks,
                "vuln_tasks": vuln_tasks,
                "vuln_perms": vuln_perms
            }

        except Exception as e:
            self.__print_exception()


    # ====================================================#
    # Purpose: Enumerates all services. Specifically we   #
    # check for vulnerable ACL's on the binpath and we    #
    # check to see if we can open the service handle with #
    # EDIT/CHANGE permissions in order to change the      #
    # binpath. These two checks are stored as boolean     #
    # values in the final report.                         #
    #                                                     #
    # Return: dict - contains number of vulns found       #
    # ====================================================#
    def analyze_all_services(self):
        try:

            fp = filepaths.filepath_enumeration(self.__output_dir, False)
            an = analyze.analyze(self.__output_dir, False)

            out_file = open(f"{self.__output_dir}/services_enumeration.txt", "a+")
            total_services = 0  # Total Number of services
            vuln_perms = 0  # Total number of services that have suspect/vulnerable permissions (ACLS)
            vuln_conf = 0  # Total number of services where we can change the binpath as a standard user.
            vuln_unquote = 0  # Total number of services with unquoted service paths
            vuln_services = []  # List of all services tht can potentially be exploited

            service_config_manager = win32service.OpenSCManager(
                "",
                None,
                win32service.SC_MANAGER_CONNECT
                | win32service.SC_MANAGER_ENUMERATE_SERVICE
                | win32service.SC_MANAGER_QUERY_LOCK_STATUS
                | win32service.SERVICE_QUERY_CONFIG,
            )
            service_manager = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE
            )

            # Hacky way to get the total number of services
            for service in win32service.EnumServicesStatus(
                service_manager,
                win32service.SERVICE_WIN32,
                win32service.SERVICE_STATE_ALL,
            ):
                total_services += 1

            pbar = tqdm(total=total_services)
            pbar.set_description("Analyzing Services")
            # For each service, enumerate its values and check ACL's / binpath edits.
            for service in win32service.EnumServicesStatus(
                service_manager,
                win32service.SERVICE_WIN32,
                win32service.SERVICE_STATE_ALL,
            ):

                acls = ""  # Holds all ACL's obtained from filepaths.py
                conf_check = False  # Can we edit the current services configuration?
                unquote_check = False  # Check for unquoted service paths

                access = win32service.OpenService(
                    service_config_manager,
                    service[0],
                    win32service.SERVICE_QUERY_CONFIG,
                )
                config = win32service.QueryServiceConfig(access)

                service_short_name = str(service[0]).replace('"', "").strip()
                service_long_name = str(service[1]).replace('"', "").strip()
                service_type = self.__access_from_int(config[0])
                service_start_type = self.__windows_objects.START_TYPE[config[2]]
                service_dependencies = str(config[6]).replace('"', "").strip()
                raw_bin_path = str(config[3])
                cleaned_bin_path = str(config[3]).replace('"', "").strip()

                # find and cleanup the bin path due to CLI argument being present.
                service_bin_path = re.findall(
                    self.__windows_file_path, 
                    cleaned_bin_path)[0]

                service_bin_path = os.path.join(
                    service_bin_path[0] + ":\\",
                    service_bin_path[1] + service_bin_path[2])

                # Analyze ACL's for the Bin Path:
                acl_list = fp.get_acl_list_return(service_bin_path)
                for i, acl in enumerate(acl_list):

                    if i == 0:
                        spacing = " " * 11
                    else:
                        spacing = " " * 16

                    if i == (len(acl_list) - 1):
                        acls += f"{spacing}{acl}"
                    else:
                        acls += f"{spacing}{acl}\n"

                # Check for bad ACL permissions:
                suspect_service = an.analyze_acls_from_list(acl_list)
                if suspect_service:
                    vuln_perms += 1
                    if service_short_name not in vuln_services:
                        vuln_services.append(service_short_name)

                # Check if we can change the config:
                try:
                    test = win32service.OpenService(
                        service_config_manager,
                        service[0],
                        win32service.SERVICE_CHANGE_CONFIG,
                    )
                    conf_check = True
                    vuln_conf += 1
                    if service_short_name not in vuln_services:
                        vuln_services.append(service_short_name)
                except:
                    pass

                # Check for unquoted service paths:
                if ("program files" in raw_bin_path.lower()
                    and '"' not in raw_bin_path.lower()):
                    unquote_check = True
                    vuln_unquote += 1
                    if service_short_name not in vuln_services:
                        vuln_services.append(service_short_name)

                # Write the final data to a file.
                data = f"""
Short Name:{" "*5}{service_short_name}
Long Name:{" "*6}{service_long_name}
Service Type:{" "*3}{config[0]} {service_type}
Start Type:{" "*5}{service_start_type}
Dependencies:{" "*3}{service_dependencies}
Full Command:{" "*3}{cleaned_bin_path}
Bin Path:{" "*7}{service_bin_path}
ACLS:{acls}
Suspect Perms:{" "*2}{suspect_service}
Change Binpath: {conf_check}
Unquoted Path:{" "*2}{unquote_check}
        """

                out_file.write(data)
                pbar.update(1)

            return {
                "total_services": total_services,
                "vuln_perms": vuln_perms,
                "vuln_conf": vuln_conf,
                "vuln_unquote": vuln_unquote,
                "vuln_services": vuln_services
            }

        except Exception as e:
            self.__print_exception()
            exit(1)

    # ==============================================#
    # Purpose: Clean Exception Printing             #
    # Return: None                                  #
    # ==============================================#
    def __print_exception(self):
        exc_type, exc_obj, tb = sys.exc_info()
        tmp_file = tb.tb_frame
        lineno = tb.tb_lineno
        filename = tmp_file.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, tmp_file.f_globals)
        print(
            f"{Fore.RED}EXCEPTION IN: {Fore.GREEN}{filename}\n\t[i] LINE: {lineno}, {line.strip()}\n\t[i] OBJECT: {exc_obj}{Fore.RESET}"
        )

    # ==============================================#
    # Purpose: Given a int permission bitmask,      #
    # translate it into an ASCII SERVICE_TYPE       #
    #                                               #
    # Return: String - Contains SERVICE_TYPE string #
    # ==============================================#
    def __access_from_int(self, num):

        rights = ""

        for spec in self.__windows_objects.SERVICE_TYPE.items():
            if num & spec[0]:
                rights += spec[1] + " "

        return rights

    # ==============================================#
    # Purpose: Given a LDAP timestamp, convert it   #
    # to datetime object.                           #
    #                                               #
    # Return: datetime object                       #
    # ==============================================#
    def __ldap_to_datetime(self,ts: float):
        fixed = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=ts/10000000)
        return fixed
