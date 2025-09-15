#!/usr/bin/env python3
import json
import argparse
import requests
import urllib3
import re
import sys

class SSVCDataNotFoundException(Exception):
    pass

class CVSSDataNotFoundException(Exception):
    pass

class CVEDataFetchException(Exception):
    pass

class CertificateVerificationFailedException(Exception):
    pass

class InvalidCVEFileException(Exception):
    pass

CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d+$')

def load_cve_data(cve_id, verify_ssl):
    year, number = cve_id.split('-')[1], cve_id.split('-')[2]
    directory = number[:-3] + "xxx"
    file_url = f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{directory}/{cve_id}.json"

    try:
        response = requests.get(file_url, verify=verify_ssl)
        response.raise_for_status()
    except requests.exceptions.SSLError as e:
        raise CertificateVerificationFailedException(
            f"SSL certificate verification failed for {file_url}."
        ) from e
    except requests.exceptions.RequestException as e:
        raise CVEDataFetchException(f"Failed to fetch data for {cve_id} from {file_url}") from e

    return response.json()

def get_decision_points(cve_data):
    try:
        adp_containers = cve_data['containers']['adp']
        for container in adp_containers:
            for metric in container.get('metrics', []):
                if 'other' in metric and metric['other']['type'] == 'ssvc':
                    options = metric['other']['content']['options']
                    exploitation = next(item['Exploitation'] for item in options if 'Exploitation' in item)
                    automatable = next(item['Automatable'] for item in options if 'Automatable' in item)
                    technical_impact = next(item['Technical Impact'] for item in options if 'Technical Impact' in item)
                    return exploitation, automatable, technical_impact
        raise SSVCDataNotFoundException("SSVC data not found in the CVE record.")
    except (KeyError, IndexError, StopIteration):
        raise SSVCDataNotFoundException("SSVC data not found in the CVE record.")

def get_detailed_info(cve_data):
    try:
        if 'cvssV3_1' in cve_data['containers']['adp'][0]['metrics'][0]:
            cvss_data = cve_data['containers']['adp'][0]['metrics'][0]['cvssV3_1']
            cwe_id = cve_data['containers']['adp'][0]['problemTypes'][0]['descriptions'][0].get('cweId', 'N/A')
            source = "adp"
        else:
            raise KeyError
    except (KeyError, IndexError):
        try:
            cvss_data = cve_data['containers']['cna']['metrics'][0]['cvssV3_1']
            cwe_id = cve_data['containers']['cna']['problemTypes'][0]['descriptions'][0].get('cweId', 'N/A')
            source = "cna"
        except (KeyError, IndexError):
            raise CVSSDataNotFoundException("CVSS data not found in the CVE record.")

    vector_parts = cvss_data['vectorString'].split('/')
    vector_dict = {part.split(':')[0]: part.split(':')[1] for part in vector_parts[1:]}

    detailed_info = (
        cvss_data['baseSeverity'],
        cvss_data['baseScore'],
        vector_dict.get('AV', 'N/A'),
        vector_dict.get('AC', 'N/A'),
        vector_dict.get('PR', 'N/A'),
        vector_dict.get('UI', 'N/A'),
        vector_dict.get('S', 'N/A'),
        vector_dict.get('C', 'N/A'),
        vector_dict.get('I', 'N/A'),
        vector_dict.get('A', 'N/A'),
        cvss_data['vectorString'],
        cwe_id,
        source
    )
    return detailed_info

def ssvc(cve_id, no_check_certificate=False):
    verify_ssl = not no_check_certificate
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cve_data = load_cve_data(cve_id, verify_ssl)
    return get_decision_points(cve_data)

def verbose(cve_id, no_check_certificate=False):
    verify_ssl = not no_check_certificate
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cve_data = load_cve_data(cve_id, verify_ssl)
    decision_points = get_decision_points(cve_data)
    try:
        detailed_info = get_detailed_info(cve_data)
        return decision_points + detailed_info
    except CVSSDataNotFoundException:
        raise CVSSDataNotFoundException(f"CVSS data not found for CVE ID: {cve_id}")

def read_cve_file(file_path):
    cve_list = []
    with open(file_path, 'r') as f:
        lines = f.read().splitlines()

    if not lines:
        raise InvalidCVEFileException("File is empty.")

    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            raise InvalidCVEFileException(f"Empty line detected at line {idx}.")
        if not CVE_PATTERN.match(line):
            raise InvalidCVEFileException(f"Invalid CVE format at line {idx}: {line}")
        cve_list.append(line.strip())

    return cve_list

def format_table(rows, header, col_widths):
    header_fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"
    row_fmt = "|" + "|".join(f" {{:<{w}}} " for w in col_widths) + "|"
    separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

    output = [separator, header_fmt.format(*header), separator.replace("-", "=")]
    for row in rows:
        output.append(row_fmt.format(*row))
        output.append(separator)
    return "\n".join(output)

def format_output(results, detailed_info=False, output_format='csv'):
    header_basic = ["CVE-ID", "Exploitation", "Automatable", "Technical Impact"]
    header_verbose = ["Severity", "Score", "AV", "AC", "PR", "UI", "S", "C", "I", "A", "Vector", "CWE", "Source"]
    col_widths_basic = [16, 13, 12, 16]
    col_widths_verbose = [8, 5, 2, 2, 2, 2, 2, 2, 2, 2, 44, 8, 6]  # Corrected width for Vector

    header = header_basic + (header_verbose if detailed_info else [])
    col_widths = col_widths_basic + (col_widths_verbose if detailed_info else [])

    if output_format == 'csv':
        return "\n".join(
            f"{cve_id},{','.join(decision_points)},{','.join(map(str, info or []))}" 
            for cve_id, decision_points, info in results
        )
    elif output_format == 'tsv':
        return "\n".join(
            f"{cve_id}\t{'\t'.join(decision_points)}\t{'\t'.join(map(str, info or []))}" 
            for cve_id, decision_points, info in results
        )
    elif output_format == 'table':
        rows = [
            [cve_id] + list(decision_points) + (list(info) if info else [])
            for cve_id, decision_points, info in results
        ]
        return format_table(rows, header, col_widths)

def main():
    parser = argparse.ArgumentParser(
        description="Fetch decision points from vulnrichment data based on CVE ID",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example usage:
Normal use (SSL verification, single CVE):
$ python3 vulnrich.py ​​-id CVE-2025-22949

In an environment where certificate verification fails due to an internal proxy, etc.:
$ python3 vulnrich.py ​​-id CVE-2025-22949 --no-check-certificate

Specify multiple CVE-IDs in a file:
$ python3 vulnrich.py ​​-f cve_list.txt
(Each line of the file contains one CVE-ID)

Display details with the -v option:
$ python3 vulnrich.py ​​-id CVE-2025-22949 -v

Specify the output format:
$ python3 vulnrich.py ​​-id CVE-2025-22949 -o tsv
$ python3 vulnrich.py ​​-id CVE-2025-22949 -o table

When importing: 
import vulnrich

# Disable SSL certificate validation and get more information
cve_id = "CVE-2025-22949"
decision_points = vulnrich.verbose(cve_id, no_check_certificate=True)
print(decision_points)

# Read CVE-IDs from a file and process each ID
cve_ids = vulnrich.read_cve_file("path/to/cve_list.txt")
for cve_id in cve_ids:
    decision_points = vulnrich.ssvc(cve_id, no_check_certificate=True)
    print(f"{cve_id},{decision_points[0]},{decision_points[1]},{decision_points[2]}")
"""
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-id', '--cve_id', help="CVE ID in the format CVE-NNNN-NNNN")
    group.add_argument('-f', '--file', help="Path to a file containing multiple CVE IDs, one per line")

    parser.add_argument(
        '--no-check-certificate',
        action='store_true',
        help="Disable SSL certificate verification (only if needed for internal proxies etc.)"
    )
    parser.add_argument('-v', '--verbose', action='store_true', help="Display detailed SSVC data")
    parser.add_argument('-o', '--output', choices=['csv', 'tsv', 'table'], default='csv', help="Output format")

    args = parser.parse_args()

    no_check_certificate = args.no_check_certificate
    output_format = args.output
    detailed_info = args.verbose

    try:
        if args.cve_id:
            cve_ids = [args.cve_id]
        else:
            cve_ids = read_cve_file(args.file)

        results = []
        for cve_id in cve_ids:
            if detailed_info:
                decision_points = verbose(cve_id, no_check_certificate)
                results.append((cve_id, decision_points[:3], decision_points[3:]))
            else:
                decision_points = ssvc(cve_id, no_check_certificate)
                results.append((cve_id, decision_points, None))

        output = format_output(results, detailed_info, output_format)
        print(output)

    except (InvalidCVEFileException, CertificateVerificationFailedException,
            SSVCDataNotFoundException, CVSSDataNotFoundException, CVEDataFetchException) as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
