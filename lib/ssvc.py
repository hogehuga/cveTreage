#!/usr/bin/env python3

import csv
import argparse
import sys
import os
import epss, kevc, vulnrich
import urllib3

DECISION_TREE_PATH = '../decisionTree/'

class DecisionTreeParseException(Exception):
    pass

def parse_decision_tree(file_path):
    decision_tree = []
    try:
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) != 5:
                    raise DecisionTreeParseException("Invalid row format in decision tree.")
                decision_tree.append(row)
    except Exception as e:
        raise DecisionTreeParseException(f"Failed to parse decision tree: {e}")
    return decision_tree

def determine_outcome(decision_tree, exploitation, automatable, technical_impact, mission=None):
    possible_outcomes = []
    for row in decision_tree:
        if row[0] == exploitation and row[1] == automatable and row[2] == technical_impact:
            if mission is None or row[3] == mission:
                possible_outcomes.append(row[4])
    return possible_outcomes

def format_output(results, output_format, verbose=False):
    if verbose:
        header = ["CVE-ID", "KEV", "Severity", "Score", "Outcome", "Exploitation", "Automatable", "TechnicalImpact", "CVSS Vector String", "Source", "EPSS", "EPSS(%)"]
        col_widths = [16, 3, 8, 5, 20, 12, 11, 15, 44, 6, 8, 8]
    else:
        header = ["CVE-ID", "Outcome", "Exploitation", "Automatable", "TechnicalImpact"]
        col_widths = [16, 20, 12, 11, 15]

    if output_format == 'csv':
        return "\n".join(
            ",".join(map(str, row)) for row in results
        )
    elif output_format == 'tsv':
        return "\n".join(
            "\t".join(map(str, row)) for row in results
        )
    elif output_format == 'table':
        header_fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"
        row_fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"
        separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

        output = [separator, header_fmt.format(*header), separator.replace("-", "=")]
        for row in results:
            output.append(row_fmt.format(*row))
            output.append(separator)
        return "\n".join(output)

def main(args):
    decision_tree_path = os.path.join(DECISION_TREE_PATH, args.tree)
    decision_tree = parse_decision_tree(decision_tree_path)

    verify_ssl = not args.no_check_certificate
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        if args.cve_id:
            cve_ids = [args.cve_id]
        else:
            cve_ids = vulnrich.read_cve_file(args.file)

        kev_data = kevc.fetch_kev_catalog(verify_ssl)
        epss_data = epss.fetch_epss_data_from_file(cve_ids, verify_ssl)

        results = []
        for cve_id in cve_ids:
            try:
                decision_points = vulnrich.ssvc(cve_id, no_check_certificate=args.no_check_certificate)
                exploitation, automatable, technical_impact = decision_points
                possible_outcomes = determine_outcome(
                    decision_tree, exploitation, automatable, technical_impact, args.mission
                )
                outcome_str = possible_outcomes[0] if args.mission else "/".join(possible_outcomes)
                if args.verbose:
                    detailed_info = vulnrich.verbose(cve_id, no_check_certificate=args.no_check_certificate)
                    kev_info = kevc.get_cve_info(cve_id, kev_data)
                    epss_info = epss_data.get(cve_id, ('N/A', 'N/A', 'N/A'))
                    result_row = (
                        cve_id,
                        kev_info['Exsist'],
                        detailed_info[3],  # Severity
                        detailed_info[4],  # Score
                        outcome_str,
                        exploitation,
                        automatable,
                        technical_impact,
                        detailed_info[13],  # CVSS Vector String
                        detailed_info[15],  # Source
                        epss_info[0],
                        epss_info[1]
                    )
                else:
                    result_row = (
                        cve_id,
                        outcome_str,
                        exploitation,
                        automatable,
                        technical_impact
                    )
                results.append(result_row)
            except Exception as e:
                print(f"Error processing {cve_id}: {e}")

        # Define the header according to verbosity
        if args.verbose:
            header = ["CVE-ID", "KEV", "Severity", "Score", "Outcome", "Exploitation", "Automatable", "TechnicalImpact", "CVSS Vector String", "Source", "EPSS", "EPSS(%)"]
        else:
            header = ["CVE-ID", "Outcome", "Exploitation", "Automatable", "TechnicalImpact"]

        # Sort results if sorting arguments are provided
        if args.sort_column:
            sort_index = header.index(args.sort_column)
            results.sort(key=lambda x: x[sort_index], reverse=(args.sort_order == 'desc'))

        output = format_output(results, args.output, args.verbose)
        print(output)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Determine SSVC outcomes for given CVE IDs",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example usage:
Normal use (SSL verification, single CVE):
$ python3 ssvc.py -id CVE-2025-22949

In an environment where certificate verification fails due to an internal proxy, etc.:
$ python3 ssvc.py -id CVE-2025-22949 --no-check-certificate

Specify multiple CVE-IDs in a file:
$ python3 ssvc.py -f cve_list.txt
(Each line of the file contains one CVE-ID)

Specify the output format:
$ python3 ssvc.py -id CVE-2025-22949 -o tsv
$ python3 ssvc.py -id CVE-2025-22949 -o table

Sort results:
$ python3 ssvc.py -f cve_list.txt -sC Severity -sO desc

When importing:
import ssvc

# Use functions to perform operations
args = parser.parse_args(["-id", "CVE-2025-22949", "--no-check-certificate"])
ssvc.main(args)
"""
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-id', '--cve_id', help="Specify a single CVE ID.")
    group.add_argument('-f', '--file', help="Specify a file containing CVE IDs, one per line.")

    parser.add_argument('-t', '--tree', default='cisa.csv', help="Specify the decision tree CSV file.")
    parser.add_argument('-m', '--mission', choices=['low', 'medium', 'high'], help="Specify mission & well-being level.")
    parser.add_argument('--no-check-certificate', action='store_true', help="Disable SSL certificate verification.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Display detailed information.")
    parser.add_argument('-o', '--output', choices=['csv', 'tsv', 'table'], default='csv', help="Output format.")

    # Change short option for sort-column to -sC
    parser.add_argument('-sC', '--sort-column', choices=['CVE-ID', 'Outcome', 'Exploitation', 'Automatable', 'TechnicalImpact', 'Severity', 'Score', 'EPSS'], help="Specify the column to sort by.")
    parser.add_argument('-sO', '--sort-order', choices=['asc', 'desc'], default='asc', help="Specify the sort order (ascending or descending).")

    return parser

if __name__ == "__main__":
    parser = parse_arguments()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    main(args)
