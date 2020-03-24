import re
import os
import sys
import linecache
import win32service
from tqdm import tqdm
from . import windows_objects, filepaths, analyze
from colorama import Fore, init
init()


class low_haning_fruit():

  def __init__(self, o_dir):
    self.name = "Low Hangning Fruit"
    self.__output_dir = o_dir
    self.__windows_objects = windows_objects.windows_services()
    self.__windows_file_path = re.compile(r'^([A-Za-z]):\\((?:[A-Za-z\d][A-Za-z\d\- \x27_\(\)~]{0,61}\\?)*[A-Za-z\d][A-Za-z\d\- \x27_\(\)]{0,61})(\.[A-Za-z\d]{1,6})?')

    

  def get_scheduled_tasks(self):
    #schtasks /query /fo LIST /v
    pass


  # ================================================#
  # Purpose: Enumerates all services. Specifically  #
  # we check for vulnerable ACL's on the binpath    #
  # and we check to see if we can open the service  #
  # handle with EDIT/CHANGE permissions in order to #
  # change the binpath. These two checks are        #
  # stored as boolean values in the final report.   #
  # Return: dict - contains number of vulns found   #
  # ================================================#
  def analyze_all_services(self):
    try:

      fp = filepaths.filepath_enumeration(self.__output_dir)
      an = analyze.analyze(self.__output_dir)

      out_file = open(f"{self.__output_dir}/services_enumeration.txt", "a+")
      total_services = 0  # Total Number of services
      vuln_perms = 0      # Total number of services that have suspect/vulnerable permissions (ACLS)
      vuln_conf = 0       # Total number of services where we can change the binpath as a standard user. 
      vuln_unquote = 0    # Total number of services with unquoted service paths

      service_config_manager = win32service.OpenSCManager('', None, win32service.SC_MANAGER_CONNECT | win32service.SC_MANAGER_ENUMERATE_SERVICE | win32service.SC_MANAGER_QUERY_LOCK_STATUS | win32service.SERVICE_QUERY_CONFIG)
      service_manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)

      # Hacky way to get the total number of services
      for service in win32service.EnumServicesStatus(service_manager, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL):
        total_services += 1

      pbar = tqdm(total=total_services)
      pbar.set_description("Analyzing Services")
      # For each service, enumerate its values and check ACL's / binpath edits.
      for service in win32service.EnumServicesStatus(service_manager, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL):
        
        acls = ""             # Holds all ACL's obtained from filepaths.py
        conf_check = False    # Can we edit the current services configuration?
        unquote_check = False  # Check for unquoted service paths

        access = win32service.OpenService(service_config_manager, service[0], win32service.SERVICE_QUERY_CONFIG)
        config = win32service.QueryServiceConfig(access)

        service_short_name = str(service[0]).replace('"','').strip()
        service_long_name = str(service[1]).replace('"','').strip()
        service_type = self.__access_from_int(config[0])
        service_start_type = self.__windows_objects.START_TYPE[config[2]]
        service_dependencies = str(config[6]).replace('"','').strip()
        raw_bin_path = str(config[3])
        cleaned_bin_path = str(config[3]).replace('"','').strip()
        
        # find and cleanup the bin path due to CLI argument being present. 
        service_bin_path = re.findall(self.__windows_file_path, cleaned_bin_path)[0]
        service_bin_path = os.path.join(service_bin_path[0]+":\\",service_bin_path[1]+service_bin_path[2])

        # Analyze ACL's for the Bin Path:
        acl_list = fp.get_acl_list_return(service_bin_path)
        for i, acl in enumerate(acl_list):

          if (i == 0):
            spacing = " " * 11
          else:
            spacing = " " * 16

          if (i == (len(acl_list)-1)):
            acls += f"{spacing}{acl}"
          else:
            acls += f"{spacing}{acl}\n"

        # Check for bad ACL permissions:
        suspect_service = an.analyze_acls_from_list(acl_list)
        if (suspect_service): 
          vuln_perms += 1

        # Check if we can change the config:
        try:
          test = win32service.OpenService(service_config_manager, service[0], win32service.SERVICE_CHANGE_CONFIG)
          conf_check = True
          vuln_conf += 1
        except:
          pass

        # Check for unquoted service paths:
        if ("program files" in raw_bin_path.lower() and '"' not in raw_bin_path.lower()):
          unquote_check = True
          vuln_unquote += 1

      
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

      return {"vuln_perms": vuln_perms, "vuln_conf": vuln_conf, "vuln_unquote":vuln_unquote}

    except Exception as e:
      self.__print_exception()
      exit(1)


  # ===============================================#
  # Purpose: Clean Exception Printing             #
  # Return: None                                  #
  # ===============================================#
  def __print_exception(self):
    exc_type, exc_obj, tb = sys.exc_info()
    tmp_file = tb.tb_frame
    lineno = tb.tb_lineno
    filename = tmp_file.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, tmp_file.f_globals)
    print(f"{Fore.RED}EXCEPTION IN: {Fore.GREEN}{filename}\n\t[i] LINE: {lineno}, {line.strip()}\n\t[i] OBJECT: {exc_obj}{Fore.RESET}")


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
