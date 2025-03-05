import requests
import json
import os
import urllib3

class KEVCatalogFetchException(Exception):
    """Exception raised when KEV Catalog data cannot be fetched."""
    pass

# Fetch KEV Catalog data
def fetch_kevc_data(no_check_certificate=False):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        if no_check_certificate:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(url, verify=not no_check_certificate)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError:
        if not no_check_certificate:
            print("SSL certificate verification failed. Please try again with the --no-check-certificate option.")
        raise KEVCatalogFetchException("Failed to fetch KEV Catalog data due to SSL certificate verification error.")
    except requests.exceptions.RequestException as e:
        raise KEVCatalogFetchException(f"Failed to fetch KEV Catalog data: {e}")

# Load KEV Catalog data from file
def load_kevc_data(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Check if CVE-ID is in KEV Catalog
def check_kevc(cve_id, kevc_data):
    for item in kevc_data['vulnerabilities']:
        if item['cveID'] == cve_id:
            return {
                "cveID": item['cveID'],
                "exist": "yes",
                "dateAdded": item['dateAdded'],
                "dueDate": item['dueDate'],
                "knownRansomwareCampaignUse": item.get('knownRansomwareCampaignUse', 'N/A')
            }
    return {
        "cveID": cve_id,
        "exist": "no",
        "dateAdded": "N/A",
        "dueDate": "N/A",
        "knownRansomwareCampaignUse": "N/A"
    }

# Main function for standalone execution
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Check if CVE-ID is in KEV Catalog")
    parser.add_argument('-id', '--cve_id', help="Specify CVE ID as a comma-separated list")
    parser.add_argument('-f', '--file', help="Specify a file containing CVE IDs")
    parser.add_argument('-L', '--lock', action='store_true', help="Use previously downloaded KEV Catalog data")
    parser.add_argument('-U', '--update', action='store_true', help="Update KEV Catalog data")
    parser.add_argument('-o', '--output', default="table", help="Specify the output format (table/csv/tsv)")
    parser.add_argument('--no-check-certificate', action='store_true', help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.cve_id and not args.file and not args.update:
        parser.print_help()
        return

    if args.update:
        try:
            kevc_data = fetch_kevc_data(args.no_check_certificate)
            with open("known_exploited_vulnerabilities.json", 'w') as file:
                json.dump(kevc_data, file)
            print("KEV Catalog data updated successfully.")
        except KEVCatalogFetchException as e:
            print(e)
        return

    cve_ids = []
    if args.cve_id:
        cve_ids = args.cve_id.split(',')
    elif args.file:
        with open(args.file, 'r') as file:
            cve_ids = [line.strip() for line in file]

    kevc_data = None
    if args.lock:
        if os.path.exists("known_exploited_vulnerabilities.json"):
            kevc_data = load_kevc_data("known_exploited_vulnerabilities.json")
        else:
            print("Error: KEV Catalog data not found. Please download the data first.")
            return
    else:
        try:
            kevc_data = fetch_kevc_data(args.no_check_certificate)
            with open("known_exploited_vulnerabilities.json", 'w') as file:
                json.dump(kevc_data, file)
        except KEVCatalogFetchException as e:
            print(e)
            return

    results = []
    for cve_id in cve_ids:
        result = check_kevc(cve_id, kevc_data)
        results.append(result)

    if args.output == "csv":
        output = "cveID,exist,dateAdded,dueDate,knownRansomwareCampaignUse\n"
        for result in results:
            output += f"{result['cveID']},{result['exist']},{result['dateAdded']},{result['dueDate']},{result['knownRansomwareCampaignUse']}\n"
    elif args.output == "tsv":
        output = "cveID\texist\tdateAdded\tdueDate\tknownRansomwareCampaignUse\n"
        for result in results:
            output += f"{result['cveID']}\t{result['exist']}\t{result['dateAdded']}\t{result['dueDate']}\t{result['knownRansomwareCampaignUse']}\n"
    else:
        output = "|cveID         |exist|dateAdded   |dueDate     |knownRansomwareCampaignUse|\n"
        output += "|--------------|-----|------------|------------|--------------------------|\n"
        for result in results:
            output += f"|{result['cveID']:<14}|{result['exist']:<5}|{result['dateAdded']:<12}|{result['dueDate']:<12}|{result['knownRansomwareCampaignUse']:<26}|\n"

    print(output)

if __name__ == "__main__":
    main()
