#!/usr/bin/env python3

import requests
import csv
import gzip
import io
import datetime
import argparse
import sys
import urllib3

class EPSSDataFetchException(Exception):
    """Exception raised when EPSS data cannot be fetched."""
    pass

class InvalidCVEFileException(Exception):
    """Exception raised for invalid CVE file format."""
    pass

def fetch_epss_data_from_file(cve_ids, verify_ssl=True):
    date = datetime.datetime.now()
    for _ in range(3):  # Try for today, yesterday, and the day before yesterday
        date_str = date.strftime('%Y-%m-%d')
        url = f"https://epss.cyentia.com/epss_scores-{date_str}.csv.gz"
        try:
            response = requests.get(url, verify=verify_ssl)
            response.raise_for_status()
            with gzip.open(io.BytesIO(response.content), 'rt') as f:
                reader = csv.reader(f)
                next(reader)  # Skip the first line
                next(reader)  # Skip the second line (header)
                epss_data = {row[0]: (row[1], row[2], date_str) for row in reader if row[0] in cve_ids}
            return epss_data
        except requests.exceptions.SSLError as e:
            raise EPSSDataFetchException(f"SSL certificate verification failed for {url}") from e
        except requests.exceptions.RequestException:
            date -= datetime.timedelta(days=1)
    
    raise EPSSDataFetchException("Failed to fetch EPSS data for the last three days.")

def read_cve_file(file_path):
    cve_ids = []
    with open(file_path, 'r') as f:
        lines = f.read().splitlines()

    if not lines:
        raise InvalidCVEFileException("File is empty.")
    
    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            raise InvalidCVEFileException(f"Empty line detected at line {idx}.")
        cve_ids.append(line.strip())
    
    return cve_ids

def format_output(results, output_format):
    if output_format == 'csv':
        return "\n".join(f"{cve_id},{epss},{percent},{date}" for cve_id, epss, percent, date in results)
    elif output_format == 'tsv':
        return "\n".join(f"{cve_id}\t{epss}\t{percent}\t{date}" for cve_id, epss, percent, date in results)
    elif output_format == 'table':
        col_widths = [16, 7, 7, 10]
        header_fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"
        row_fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"
        separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

        output = [
            separator,
            header_fmt.format("CVE-ID", "EPSS", "Percent", "Date"),
            separator.replace("-", "=")
        ]
        for cve_id, epss, percent, date in results:
            output.append(row_fmt.format(cve_id, epss, percent, date))
            output.append(separator)
        return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(
        description="Fetch EPSS data for given CVE IDs",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example usage:
Normal use (SSL verification, single CVE):
$ python3 epss.py -id CVE-2025-22949

In an environment where certificate verification fails due to an internal proxy, etc.:
$ python3 epss.py -id CVE-2025-22949 --no-check-certificate

Specify multiple CVE-IDs in a file:
$ python3 epss.py -f cve_list.txt
(Each line of the file contains one CVE-ID)

Specify the output format:
$ python3 epss.py -id CVE-2025-22949 -o tsv
$ python3 epss.py -id CVE-2025-22949 -o table

When importing:
import epss

# Disable SSL certificate validation and get EPSS data
cve_id = "CVE-2025-22949"
epss_data = epss.fetch_epss_data_from_file([cve_id], verify_ssl=False)
print(epss_data)

# Read CVE-IDs from a file and process each ID
cve_ids = epss.read_cve_file("path/to/cve_list.txt")
for cve_id in cve_ids:
    epss_value, percentile, date = epss_data.get(cve_id, ('N/A', 'N/A', 'N/A'))
    print(f"{cve_id},{epss_value},{percentile},{date}")
"""
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-id', '--cve_id', help="Specify CVE ID as a comma-separated list")
    group.add_argument('-f', '--file', help="Specify a file containing CVE IDs")
    parser.add_argument('--no-check-certificate', action='store_true', help="Disable SSL certificate verification")
    parser.add_argument('-o', '--output', choices=['csv', 'tsv', 'table'], default='csv', help="Output format")

    # Check if no arguments are passed and print help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    verify_ssl = not args.no_check_certificate

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        if args.cve_id:
            cve_ids = args.cve_id.split(',')
        else:
            # Validate the file before downloading the CSV
            cve_ids = read_cve_file(args.file)

        results = []
        try:
            epss_data = fetch_epss_data_from_file(cve_ids, verify_ssl)
            for cve_id in cve_ids:
                epss, percent, date = epss_data.get(cve_id, ('N/A', 'N/A', 'N/A'))
                results.append((cve_id, epss, percent, date))
        except EPSSDataFetchException as e:
            print(f"Error: {e}")
            sys.exit(1)

        output = format_output(results, args.output)
        print(output)

    except (InvalidCVEFileException, EPSSDataFetchException) as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
