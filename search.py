import os
import sys
import csv
import argparse
import linecache
from src import analyze, low_fruit
from colorama import Fore, init
init()


# ---------------------------------------------------#
# Windows Process Information:                      #
# This script / set of scripts is designed to take  #
# the CSV output of a Procmon.exe sessions and      #
# analyze HKLM Registry keys, File, and Filepaths   #
# that were accessed by a High/System integrity     #
# context. The analysis is conducted by pulling the #
# objects current DACL via the win32api.            #
#                                                   #
# Author: @Jfaust0                                  #
# Site: SevroSecurity.com                           #
# ---------------------------------------------------#


"""
+---------------------------------------------------------------+
| python3 search.py -p <procmon_data.csv> -o <output_dir> -t 23 |
+---------------------------+-----------------------------------+
                            |
        +-------------------v---------------------+       +--------------------------------+
        |Parse Procmon: analyze.parse_procmon_csv |       |   filepaths.get_acl_list()     |
        |Output:        cleaned_paths.txt         |   +--->              or                |
        +-------------------+---------------------+   |   |    registry.get_acl_list()     |
                            |                         |   +---------------+----------------+
        +-------------------v---------------------+   |                   |
        | Analyze Paths/Keys in cleaned_paths.txt |   |   +---------------v----------------+
        +-------------------+---------------------+   |   |  filepaths.__write_to_file()   |
                            |                         |   |              or                |
        +-------------------v---------------------+   |   |   registry.__write_to_file()   |
        |       analyze.build_command_list()      |   |   |                                |
        +-------------------+---------------------+   |   |Output:  raw_acls.txt           |
                            |                         |   +----------------+---------------+
        +-------------------v---------------------+   |                    |
        |       analyze.__thread_commands()       +---+                    |
        +-----------------------------------------+                        |
                                                                           |
        +-----------------------------------------+                        |
        |         analyze.analyze_acls()          +<-----------------------+
        |Output: evil.xlsx                        |
        +-----------------------------------------+

"""


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


# =======================================#
# MAIN                                  #
# =======================================#
if __name__ == "__main__":
    try:
        
        parser = argparse.ArgumentParser()
        me = parser.add_mutually_exclusive_group()
        me.add_argument(
            "-p",
            "--procmon",
            dest="p",
            default=None,
            metavar="",
            required=False,
            help="Path to the Procmon Output File (CSV)",
        )
        me.add_argument(
            "-a",
            "--acl",
            dest="acl",
            default=None,
            metavar="",
            required=False,
            help="Analyze a singular acls.txt file",
        )
        me.add_argument(
            "-f",
            "--files",
            dest="analysis_path",
            default=None,
            metavar='',
            required=False,
            help="Analyze all files (Recursive) given a path"
        )
        me.add_argument(
            "-F",
            "--fruit",
            action="store_true",
            dest="fruit",
            required=False,
            help="Run a full analysis (Low Hanging Fruit)"
        )
        parser.add_argument(
            "-t",
            "--threads",
            metavar="",
            dest="threads",
            type=int,
            default=10,
            required=False,
            help="Defined number of threads (Max 100). Default=10",
        )
        parser.add_argument(
            "-o",
            "--out",
            dest="o",
            metavar="",
            required=True,
            help="Output location for results.",
        )
        args = parser.parse_args()

        # Check to make sure output path is valid:
        if not os.path.exists(args.o):
            print(f"[!] {args.o} does not exist")
            exit(1)

       

        if (args.p != None):

            a = analyze.analyze(args.o, True)

            # Check to make sure Procmon File is CSV:
            with open(args.p, "r") as f:
                if not csv.Sniffer().has_header(f.read(2014)):
                    print(f"[!] {str(args.p).strip()} is not a CSV file.")
                    exit(1)

            # Start the Enumeration.
            a.parse_procmon_csv(args.p)  # Analyze the Procmon CSV File and pull out paths
            total_analyzed = a.build_command_list_procmon(args.threads)  # Send paths to aggregateCommands with totla Thread Count
            interesting_items = a.analyze_acls()  # Analyze all the ACLs in raw_acls.txt
            
            print("-" * 125)
            print(f"\n[i] A total of {total_analyzed} objects Were Analyzed.")
            print(f"[i] {interesting_items} Were found to have Write or FullContol Permissions.")
            print(f"[i] {a.get_error_count()} ERRORS occurred during the analysis.")
            print("[i] Output Files:")
            print(f"\t+ {args.o}raw_acls.txt:\t\tRaw output of Access Control Listings")
            print(f"\t+ {args.o}cleaned_paths.txt:\tCleaned Up procmon output (de-duplication)")
            print(f"\t+ {args.o}evil.xlsx:\t\tKeys denoted as improperly configured/interesting")
            print(f"\t+ {args.o}errors.txt:\t\tDetails of all errors observed")

        if (args.acl != None):
            a = analyze.analyze(args.o, True)
            interesting_items = a.analyze_acls_from_file(args.acl)
            print("-" * 125)
            print(f"[i] {interesting_items} Were found to have Write or FullContol Permissions.")
            print("[i] Output Files:")
            print(f"\t+ {args.o}data.xlsx:\t\tKeys denoted as improperly configured/interesting")

        if (args.analysis_path != None):
            total_analyzed = a.build_command_list_path(args.threads, args.analysis_path)
            interesting_items = a.analyze_acls()

            print("-" * 125)
            print(f"\n[i] A total of {total_analyzed} objects Were Analyzed.")
            print(f"[i] {interesting_items} Were found to have Write or FullContol Permissions.")
            print(f"[i] {a.get_error_count()} ERRORS occurred during the analysis.")
            print("[i] Output Files:")
            print(f"\t+ {args.o}raw_acls.txt:\t\tRaw output of Access Control Listings")
            print(f"\t+ {args.o}evil.xlsx:\t\tKeys denoted as improperly configured/interesting")
            print(f"\t+ {args.o}errors.txt:\t\tDetails of all errors observed")

        if (args.fruit):
            low = low_fruit.low_haning_fruit(args.o)
            '''
            # Analyze System Services
            service_analysis = low.analyze_all_services()
            vulnerable_services = service_analysis["vuln_services"]

            # Analyze Scheduled Tasks
            tasks_analysis = low.analyze_scheduled_tasks()
            vulnerable_tasks = tasks_analysis["vuln_tasks"]

            # Analyze all files for credentials
            credential_analysis = low.look_for_credentials()

            print("-" * 125)
            print(f"[i] Windows Services:")
            print(f"\t+ Total Numer of Windows Services: {service_analysis['total_services']}")
            print(f"\t+ {service_analysis['vuln_perms']} Services have suspect/vulnerable ACL's.")
            print(f"\t+ {service_analysis['vuln_conf']} Services can have their binpath changed by a standard user.")
            print(f"\t+ {service_analysis['vuln_unquote']} Services have unquoted service paths (Hijack Execution Flow)")
            print(f"\t+ {args.o}services_enumeration.txt: All Services and enumerated objects")
            if (len(vulnerable_services) != 0):
                print(f"\t+ All Vulnerable Services: {vulnerable_services}")

            print(f"\n[i] Windows Scheduled Tasks:")
            print(f"\t+ Total Number of Scheduled Tasks: {tasks_analysis['total_tasks']}")
            print(f"\t+ {tasks_analysis['vuln_perms']} Services have suspect/vulnerable ACL's.")
            print(f"\t+ {args.o}scheduled_tasks_enumeration.txt: All analyzed scheduled tasks")
            if (len(vulnerable_services) != 0):
                print(f"\t+ All Vulnerable Tasks: {vulnerable_tasks}")
            
            print(f"\n[i] Credential Analysis:")
            print(f"\t+ {credential_analysis['total_cred_files']} Files found to possibly contain Passwords/Credentials")
            print(f"\t+ {args.o}credential_enumeration.txt: Contains Filepaths and Possible Credentials.")
            '''
            low.registry_analysis()

        exit(0)


    except Exception as e:
        print_exception()
        exit(1)
