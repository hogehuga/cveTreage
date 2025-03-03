#!/usr/bin/env python3
import argparse
import datetime
from lib.ssvc_decision import load_decision_tree, ssvc_decision, verbose_ssvc_decision
from lib.output_format import format_output
from lib.epssget import fetch_epss_data, fetch_epss_data_from_file, EPSSDataFetchException

# Main function
def main():
    parser = argparse.ArgumentParser(description="SSVC Decision Program")
    parser.add_argument('-id', '--cve_id', help="Specify CVE ID as a comma-separated list")
    parser.add_argument('-f', '--file', help="Specify a file containing CVE IDs")
    parser.add_argument('-t', '--tree', default="cisa", help="Specify the Decision Tree to use")
    parser.add_argument('-m', '--mission', help="Specify the value for Mission & Well-being (low/medium/high)")
    parser.add_argument('-o', '--output', default="table", help="Specify the output format (table/csv/tsv)")
    parser.add_argument('--verbose', action='store_true', help="Display detailed information")
    parser.add_argument('--no-check-certificate', action='store_true', help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.cve_id and not args.file:
        parser.print_help()
        return

    try:
        tree = load_decision_tree(args.tree)
    except FileNotFoundError as e:
        print(e)
        return

    cve_ids = []
    if args.cve_id:
        cve_ids = args.cve_id.split(',')
    elif args.file:
        with open(args.file, 'r') as file:
            cve_ids = [line.strip() for line in file]

    results = []
    for cve_id in cve_ids:
        try:
            if args.verbose:
                if args.mission:
                    result = verbose_ssvc_decision(cve_id, tree, args.mission, args.no_check_certificate)
                    results.extend(result)
                else:
                    result = verbose_ssvc_decision(cve_id, tree, no_check_certificate=args.no_check_certificate)
                    results.extend(result)
            else:
                if args.mission:
                    result = ssvc_decision(cve_id, tree, args.mission, args.no_check_certificate)
                    results.extend(result)
                else:
                    result = ssvc_decision(cve_id, tree, no_check_certificate=args.no_check_certificate)
                    results.extend(result)
        except KeyError as e:
            print(f"Error processing {cve_id}: {e}")

    if args.cve_id:
        for cve_id in cve_ids:
            try:
                epss, percentile = fetch_epss_data(cve_id)
                for i, result in enumerate(results):
                    if result[0] == cve_id:
                        results[i] = result + (epss, percentile)
            except EPSSDataFetchException as e:
                print(e)
    elif args.file:
        date = datetime.datetime.now().strftime('%Y-%m-%d')
        while True:
            try:
                epss_data = fetch_epss_data_from_file(cve_ids, date, args.no_check_certificate)
                for cve_id in cve_ids:
                    epss, percentile = epss_data.get(cve_id, ('N/A', 'N/A'))
                    for i, result in enumerate(results):
                        if result[0] == cve_id:
                            results[i] = result + (epss, percentile)
                break
            except EPSSDataFetchException:
                date = (datetime.datetime.strptime(date, '%Y-%m-%d') - datetime.timedelta(days=1)).strftime('%Y-%m-%d')

    output = format_output(results, args.output, args.mission, args.verbose)
    print(output)

if __name__ == "__main__":
    main()
