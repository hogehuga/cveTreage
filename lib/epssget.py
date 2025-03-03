import requests
import csv
import gzip
import io
import os
import datetime

class EPSSDataFetchException(Exception):
    """Exception raised when EPSS data cannot be fetched."""
    pass

# Fetch EPSS data from API
def fetch_epss_data(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json().get('data', [{}])[0]
        return data.get('epss', 'N/A'), data.get('percentile', 'N/A')
    else:
        raise EPSSDataFetchException(f"Failed to fetch EPSS data for {cve_id}")

# Fetch EPSS data from CSV file
def fetch_epss_data_from_file(cve_ids, date, no_check_certificate=False):
    url = f"https://epss.cyentia.com/epss_scores-{date}.csv.gz"
    response = requests.get(url, verify=not no_check_certificate)
    if response.status_code == 200:
        with gzip.open(io.BytesIO(response.content), 'rt') as f:
            reader = csv.reader(f)
            next(reader)  # Skip the first line
            next(reader)  # Skip the second line (header)
            epss_data = {row[0]: (row[1], row[2]) for row in reader if row[0] in cve_ids}
            return epss_data
    else:
        raise EPSSDataFetchException(f"Failed to fetch EPSS data for date {date}")

# Main function for standalone execution
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Fetch EPSS data for given CVE IDs")
    parser.add_argument('-id', '--cve_id', help="Specify CVE ID as a comma-separated list")
    parser.add_argument('-f', '--file', help="Specify a file containing CVE IDs")
    parser.add_argument('--no-check-certificate', action='store_true', help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.cve_id and not args.file:
        parser.print_help()
        return

    cve_ids = []
    if args.cve_id:
        cve_ids = args.cve_id.split(',')
    elif args.file:
        with open(args.file, 'r') as file:
            cve_ids = [line.strip() for line in file]

    no_check_certificate = args.no_check_certificate

    if args.cve_id:
        for cve_id in cve_ids:
            try:
                epss, percentile = fetch_epss_data(cve_id)
                print(f"{cve_id}: EPSS={epss}, Percentile={percentile}")
            except EPSSDataFetchException as e:
                print(e)
    elif args.file:
        date = datetime.datetime.now().strftime('%Y-%m-%d')
        while True:
            try:
                epss_data = fetch_epss_data_from_file(cve_ids, date, no_check_certificate)
                for cve_id in cve_ids:
                    epss, percentile = epss_data.get(cve_id, ('N/A', 'N/A'))
                    print(f"{cve_id}: EPSS={epss}, Percentile={percentile}")
                break
            except EPSSDataFetchException:
                date = (datetime.datetime.strptime(date, '%Y-%m-%d') - datetime.timedelta(days=1)).strftime('%Y-%m-%d')

if __name__ == "__main__":
    main()
