#!/usr/bin/env python3
import json
import argparse
import requests
import urllib3
import re
import sys

CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d+$')
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class InvalidCVEFileException(Exception):
    pass

class CVEDataFetchException(Exception):
    pass

def fetch_kev_catalog(verify_ssl):
    try:
        response = requests.get(KEV_CATALOG_URL, verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError as e:
        raise CVEDataFetchException("SSL Certificate error. Use --no-check-certificate option.") from e
    except requests.exceptions.RequestException as e:
        raise CVEDataFetchException("Failed to fetch KEV catalog.") from e

def read_cve_file(file_path):
    cve_ids = []
    with open(file_path, 'r') as file:
        for idx, line in enumerate(file, start=1):
            cve_id = line.strip()
            if not CVE_PATTERN.match(cve_id):
                raise InvalidCVEFileException(f"Invalid CVE format at line {idx}: {cve_id}")
            cve_ids.append(cve_id)
    if not cve_ids:
        raise InvalidCVEFileException("CVE file is empty.")
    return cve_ids

def get_cve_info(cve_id, kev_data):
    for item in kev_data.get('vulnerabilities', []):
        if item.get('cveID') == cve_id:
            return {
                'CVE-ID': cve_id,
                'Exsist': 'yes',
                'DateAdded': item.get('dateAdded', ''),
                'RansomUse': item.get('knownRansomwareCampaignUse', ''),
                'Vendor': item.get('vendorProject', ''),
                'Product': item.get('product', ''),
                'CWEs': ', '.join(item.get('cwes', [])),
                'Vulnerability Name': item.get('vulnerabilityName', ''),
            }
    return {
        'CVE-ID': cve_id,
        'Exsist': 'no',
        'DateAdded': '',
        'RansomUse': '',
        'Vendor': '',
        'Product': '',
        'CWEs': '',
        'Vulnerability Name': '',
    }

def format_output(data, output_format, verbose):
    if verbose:
        fields = ['CVE-ID', 'Exsist', 'DateAdded', 'RansomUse', 'Vendor', 'Product', 'CWEs', 'Vulnerability Name']
        col_widths = [16, 6, 10, 9, max(len(item['Vendor']) for item in data), max(len(item['Product']) for item in data), 9, 55]
    else:
        fields = ['CVE-ID', 'Exsist', 'DateAdded', 'RansomUse', 'Vendor', 'Product']
        col_widths = [16, 6, 10, 9, max(len(item['Vendor']) for item in data), max(len(item['Product']) for item in data)]

    if output_format == 'csv':
        return "\n".join(",".join(item[field] for field in fields) for item in data)
    elif output_format == 'tsv':
        return "\n".join("\t".join(item[field] for field in fields) for item in data)
    elif output_format == 'table':
        header = "|".join(f"{field:<{col_widths[idx]}}" for idx, field in enumerate(fields))
        separator = "+".join("-" * width for width in col_widths)
        underlined_header = "+".join("=" * width for width in col_widths)

        rows = "\n".join("|" + "|".join(f"{item[field]:<{col_widths[idx]}}" for idx, field in enumerate(fields)) + "|"
                         for item in data)
        return f"+{separator}+\n|{header}|\n+{underlined_header}+\n{rows}\n+{separator}+"

def main():
    parser = argparse.ArgumentParser(
        description="Fetch data from CISA's Known Exploited Vulnerability Catalog.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example usage:
Normal use (SSL verification, single CVE):
$ ./kevc.py -id CVE-2023-12345

In an environment where certificate verification fails due to an internal proxy, etc.:
$ ./kevc.py -id CVE-2023-12345 --no-check-certificate

Specify multiple CVE-IDs in a file:
$ ./kevc.py -f cve_list.txt
(Each line of the file contains one CVE-ID)

Display details with the -v option:
$ ./kevc.py -id CVE-2023-12345 -v

Specify the output format:
$ ./kevc.py -id CVE-2023-12345 -o tsv
$ ./kevc.py -id CVE-2023-12345 -o table

When importing:
import kevc

# Disable SSL certificate validation and get more information
cve_id = "CVE-2023-12345"
kev_data = kevc.fetch_kev_catalog(verify_ssl=False)
cve_info = kevc.get_cve_info(cve_id, kev_data)
print(cve_info)

# Read CVE-IDs from a file and process each ID
cve_ids = kevc.read_cve_file("path/to/cve_list.txt")
kev_data = kevc.fetch_kev_catalog(verify_ssl=False)
for cve_id in cve_ids:
    cve_info = kevc.get_cve_info(cve_id, kev_data)
    print(cve_info)
"""
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-id', '--cve_id', help="Specify a single CVE ID.")
    group.add_argument('-f', '--file', help="Specify a file containing CVE IDs, one per line.")

    parser.add_argument('--no-check-certificate', action='store_true', help="Disable SSL certificate verification.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Display detailed information.")
    parser.add_argument('-o', '--out', choices=['csv', 'tsv', 'table'], default='csv', help="Output format.")

    args = parser.parse_args()

    verify_ssl = not args.no_check_certificate
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        if args.cve_id:
            cve_ids = [args.cve_id]
        else:
            cve_ids = read_cve_file(args.file)

        kev_data = fetch_kev_catalog(verify_ssl)
        results = [get_cve_info(cve_id, kev_data) for cve_id in cve_ids]

        output = format_output(results, args.out, args.verbose)
        print(output)

    except (InvalidCVEFileException, CVEDataFetchException) as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
