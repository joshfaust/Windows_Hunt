import os
import sys
import csv
import argparse
import linecache
import pandas as pd
from io import StringIO
from tabulate import tabulate
from src import analyze, low_fruit, permissions, reporting
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


def testing():
    l = low_fruit.low_haning_fruit("./out")
    l.path_analysis()
    exit(0)



# =======================================#
# MAIN                                  #
# =======================================#
if __name__ == "__main__":
    try:
        
        #testing()

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
            "-r",
            "--report",
            default="excel",
            dest="report",
            required=False,
            help="Output Format of Final Report [Excel, JSON]"
        )
        parser.add_argument(
            "-t",
            "--threads",
            metavar="",
            dest="t",
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

            # Check to make sure Procmon File is CSV:
            with open(args.p, "r") as f:
                if not csv.Sniffer().has_header(f.read(2014)):
                    print(f"[!] {str(args.p).strip()} is not a CSV file.")
                    exit(1)

            # Start the Enumeration.
            a = analyze.analyze(args.o)                                         # Analysis Class Object
            parsed_df = a.parse_procmon_csv(args.p)                             # parse the Procmon CSV (Return: Pandas DataFrame)
            total_analyzed = a.build_command_list_procmon(args.t, parsed_df)    # Pull all ACLs for paths (threaded)
            interesting_items = a.analyze_acls_procmon()                        # Analyze all the enumerate ACLS.
            
            print("-" * 125)
            print(f"\n[i] A total of {total_analyzed} objects Were Analyzed.")
            print(f"[i] {interesting_items} Were found to have Write or FullContol Permissions.")
            print(f"[i] {a.get_error_count()} ERRORS occurred during the analysis.")
            print("[i] Output Files:")
            print(f"\t+ {args.o}raw_acls.txt:\t\tRaw output of Access Control Listings")
            print(f"\t+ {args.o}cleaned_paths.txt:\tCleaned Up procmon output (de-duplication)")
            print(f"\t+ {args.o}evil.xlsx:\t\tKeys denoted as improperly configured/interesting")
            print(f"\t+ {args.o}errors.txt:\t\tDetails of all errors observed")


        if (args.analysis_path != None):
            a = analyze.analyze(args.o)                                         # Analysis Class Object
            total_analyzed = a.build_command_list_path(args.t, args.analysis_path)
            interesting_items = a.analyze_acls_path()

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
            rep = reporting.report(args.report, args.o)
            
            # Analyze System Services
            service_analysis = low.analyze_all_services()
            # Analyze Scheduled Tasks
            tasks_analysis = low.analyze_scheduled_tasks()
            # Analyze Registry Keys:
            registry_analysis = low.registry_analysis()
            # Analyze Event Message Logging DLLs:
            message_analysis = low.message_event_analysis()
            # Analyze all files for credentials
            credential_analysis = low.look_for_credentials()
            
            report_table = rep.generate_fruit_report(service_analysis, tasks_analysis, registry_analysis, message_analysis, credential_analysis)
            print("\n\n")
            print(tabulate(report_table, headers='keys', tablefmt="psql"))
            
            

            
        exit(0)

    except Exception as e:
        print_exception()
        exit(1)
