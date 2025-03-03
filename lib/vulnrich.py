#!/usr/bin/env python3
import json
import argparse
import requests
import urllib3

class SSVCDataNotFoundException(Exception):
    """Exception raised when SSVC data is not found in the CVE record."""
    pass

class CVSSDataNotFoundException(Exception):
    """Exception raised when CVSS data is not found in the CVE record."""
    pass

class CVEDataFetchException(Exception):
    """Exception raised when CVE data cannot be fetched."""
    pass

# Load CVE data from vulnrichment
def load_cve_data(cve_id, verify_ssl):
    year, number = cve_id.split('-')[1], cve_id.split('-')[2]
    directory = number[:-3] + "xxx"
    file_url = f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{directory}/{cve_id}.json"
    response = requests.get(file_url, verify=verify_ssl)
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data
    else:
        raise CVEDataFetchException(f"Failed to fetch data for {cve_id} from {file_url}")

# Get decision points from CVE data
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

# Get detailed info from CVE data
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
        vector_dict['AV'],
        vector_dict['AC'],
        vector_dict['PR'],
        vector_dict['UI'],
        vector_dict['S'],
        vector_dict['C'],
        vector_dict['I'],
        vector_dict['A'],
        cvss_data['vectorString'],
        cwe_id,
        source
    )
    return detailed_info

# Function to be called from other scripts
def ssvc(cve_id, no_verify=False):
    verify_ssl = not no_verify
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cve_data = load_cve_data(cve_id, verify_ssl)
    return get_decision_points(cve_data)

def verbose(cve_id, no_verify=False):
    verify_ssl = not no_verify
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cve_data = load_cve_data(cve_id, verify_ssl)
    decision_points = get_decision_points(cve_data)
    try:
        detailed_info = get_detailed_info(cve_data)
        return decision_points + detailed_info
    except CVSSDataNotFoundException:
        raise CVSSDataNotFoundException("CVSS data not found for CVE ID: " + cve_id)

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="Fetch decision points from vulnrichment data based on CVE ID",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example usage:
$ python3 vulnrich.py -id CVE-2025-22949 --no-verify

or

import vulnrich
cve_id = "CVE-2025-22949"
no_verify = True  # Disable SSL verification
decision_points = vulnrich.ssvc(cve_id, no_verify)
print(decision_points)

verbose = True  # Display detailed data
decision_points = vulnrich.verbose(cve_id, no_verify)
print(decision_points)
"""
    )
    parser.add_argument('-id', '--cve_id', required=True, help="CVE ID in the format CVE-NNNN-NNNN")
    parser.add_argument('--no-verify', action='store_true', help="Disable SSL certificate verification")
    parser.add_argument('-v', '--verbose', action='store_true', help="Display detailed SSVC data")

    args = parser.parse_args()

    try:
        # Set SSL verification option
        verify_ssl = not args.no_verify
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if args.verbose:
            decision_points = verbose(args.cve_id, not verify_ssl)
            print(decision_points)
        else:
            decision_points = ssvc(args.cve_id, not verify_ssl)
            # Output as comma-separated values
            print(f"{decision_points[0]},{decision_points[1]},{decision_points[2]}")
    except SSVCDataNotFoundException as e:
        print(f"Error: {e}")
    except CVSSDataNotFoundException as e:
        print(f"Error: {e}")
    except CVEDataFetchException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
