import os
import sys
import linecache
import pandas as pd
from colorama import Fore, init
init()


class report:

    def __init__(self, report_format, o_dir):
        self.name = "Report Generation"
        self.__report_format = report_format.lower()
        self.__output_dir = o_dir
        
    # ==========================================================#
    # Purpose:  Takes several dictionaries from the low_fruit   #
    #           analysis and compiles a file report in one of   #
    #           two formats (Excel, JSON). It also builds a     #
    #           dataframe that is a very high-level view of the # 
    #           overall analysis                                #
    # Return:   dataframe                                       #
    # ==========================================================#
    def generate_fruit_report(self, services: dict, tasks: dict, registry: dict, message_events: dict, creds: dict):
        try:
            fruit_report = pd.DataFrame(columns=["Analysis", "Description", "Analysis Type", "Issues Found"])

            # Analyze System Services
            services_name = services["name"]
            services_desc = services["description"]
            services_report = services["dataframe"]
            services_total = services["total_services"]
            services_vuln_perms = services["vuln_perms"]
            services_vuln_conf = services["vuln_conf"]
            services_vuln_unquote = services["vuln_unquote"]

            fruit_report = fruit_report.append({
                "Analysis": services_name, 
                "Description": services_desc, 
                "Analysis Type": "Total Services",
                "Issues Found": services_total}, ignore_index=True)
            fruit_report = fruit_report.append({
                "Analysis": services_name, 
                "Description": services_desc, 
                "Analysis Type": "Unquoted Service Paths",
                "Issues Found": services_vuln_unquote}, ignore_index=True)
            fruit_report = fruit_report.append({
                "Analysis": services_name, 
                "Description": services_desc, 
                "Analysis Type": "Weak Permissions",
                "Issues Found": services_vuln_perms}, ignore_index=True)
            fruit_report = fruit_report.append({
                "Analysis": services_name, 
                "Description": services_desc, 
                "Analysis Type": "Editable Configuration",
                "Issues Found": services_vuln_conf}, ignore_index=True)

            # Analyze Scheduled Tasks
            tasks_name = tasks["name"]
            tasks_desc = tasks["description"]
            tasks_report = tasks["dataframe"]
            tasks_total = tasks["total_tasks"]
            tasks_vuln_perms = tasks["vuln_perms"]

            fruit_report = fruit_report.append({
                "Analysis": tasks_name, 
                "Description": tasks_desc, 
                "Analysis Type": "Total Scheduled Tasks",
                "Issues Found": tasks_total}, ignore_index=True)

            fruit_report = fruit_report.append({
                "Analysis": tasks_name, 
                "Description": tasks_desc, 
                "Analysis Type": "Weak Permissions",
                "Issues Found": tasks_vuln_perms}, ignore_index=True)

            # Analyze Registry Keys:
            registry_name = registry["name"]
            registry_desc = registry["description"]
            registry_report = registry["dataframe"]

            fruit_report = fruit_report.append({
                "Analysis": registry_name, 
                "Description": registry_desc, 
                "Analysis Type": "Common Key Analysis",
                "Issues Found": "Review Final Report"}, ignore_index=True)

            # Analyze Event Message Logging DLLs:
            message_name = message_events["name"]
            message_desc = message_events["description"]
            message_report = message_events["dataframe"]
            message_vuln_perms = message_events["vuln_perms"]

            fruit_report = fruit_report.append({
                "Analysis": message_name, 
                "Description": message_desc, 
                "Analysis Type": "Weak Permissions",
                "Issues Found": message_vuln_perms}, ignore_index=True)

            # Analyze all files for credentials
            credential_name = creds["name"]
            credential_desc = creds["description"]
            credential_report = creds["dataframe"]
            credential_found = creds["total_cred_files"]

            fruit_report = fruit_report.append({
                "Analysis": credential_name, 
                "Description": credential_desc, 
                "Analysis Type": "Possible Credentials Files",
                "Issues Found": credential_found}, ignore_index=True)

            # Write Final Report Excel:
            if (self.__report_format == "excel"):
                with pd.ExcelWriter(f"{self.__output_dir}/Priv_Esc_Analysis.xlsx") as writer:
                    fruit_report.to_excel(writer, sheet_name="totals")
                    services_report.to_excel(writer, sheet_name=services_name)
                    tasks_report.to_excel(writer, sheet_name=tasks_name)
                    message_report.to_excel(writer, sheet_name=message_name)
                    registry_report.to_excel(writer, sheet_name=registry_name)
                    credential_report.to_excel(writer, sheet_name=credential_name)

            # Write Final Reports JSON:
            if (self.__report_format == "json"):
                    services_report.to_json(f"{self.__output_dir}/{services_name.replace(' ', '_')}.json", orient="table")
                    tasks_report.to_json(f"{self.__output_dir}/{tasks_name.replace(' ', '_')}.json", orient="table")
                    message_report.to_json(f"{self.__output_dir}/{message_name.replace(' ', '_')}.json", orient="table")
                    registry_report.to_json(f"{self.__output_dir}/{registry_name.replace(' ', '_')}.json", orient="table")   
                    credential_report.to_json(f"{self.__output_dir}/{credential_name.replace(' ', '_')}.json", orient="table")   

            return fruit_report

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




