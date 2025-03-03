# cveTreage
CVE-ID vulnerability triage programs. It is aimed at those who have not yet implemented vulnerability management and want to take their skills to the next level, as well as those who have already implemented vulnerability management to improve their skills.

**NOW Beta Preview version**

Main triage program Usage:

```
$ ./ssvcout.py -h
usage: ssvcout.py [-h] [-id CVE_ID] [-f FILE] [-t TREE] [-m MISSION] [-o OUTPUT] [--verbose] [--no-check-certificate]

SSVC Decision Program

options:
  -h, --help            show this help message and exit
  -id CVE_ID, --cve_id CVE_ID
                        Specify CVE ID as a comma-separated list
  -f FILE, --file FILE  Specify a file containing CVE IDs
  -t TREE, --tree TREE  Specify the Decision Tree to use
  -m MISSION, --mission MISSION
                        Specify the value for Mission & Well-being (low/medium/high)
  -o OUTPUT, --output OUTPUT
                        Specify the output format (table/csv/tsv)
  --verbose             Display detailed information
  --no-check-certificate
                        Disable SSL certificate verification
$ ./ssvcout.py --no-check-certificate -id CVE-2025-21391
|CVE-ID         |Outcome           |Exploitation|Automatable|Technical Impact|
|---------------|------------------|------------|-----------|----------------|
|CVE-2025-21391 |Track/Attend/Act  |active      |no         |total           |

$ ./ssvcout.py --no-check-certificate -id CVE-2025-21391 -m high
|CVE-ID         |Outcome|Exploitation|Automatable|Technical Impact|Mission & Well-being|
|---------------|-------|------------|-----------|----------------|--------------------|
|CVE-2025-21391 |Act    |active      |no         |total           |high                |

$ ./ssvcout.py --no-check-certificate -id CVE-2025-21391 --verbose
|CVE-ID         |Severity|Score|Outcome           |Exploitation|Automatable|Technical Impact|CVSS Vector String                           |Source|EPSS        |EPSS(%)     |
|---------------|--------|-----|------------------|------------|-----------|----------------|---------------------------------------------|------|------------|------------|
|CVE-2025-21391 |HIGH    |7.1  |Track/Attend/Act  |active      |no         |total           |CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H/E:F/RL:O/RC:C|cna   |0.000880000 |0.399220000 |

$ ./ssvcout.py --no-check-certificate -id CVE-2025-21391 --verbose -o csv
CVE-2025-21391,HIGH,7.1,Track/Attend/Act,active,no,total,CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H/E:F/RL:O/RC:C,cna,0.000880000,0.399220000

$
```

sub library programs

```
$ ./vulnrich.py -h
usage: vulnrich.py [-h] -id CVE_ID [--no-verify] [-v]

Fetch decision points from vulnrichment data based on CVE ID

options:
  -h, --help            show this help message and exit
  -id CVE_ID, --cve_id CVE_ID
                        CVE ID in the format CVE-NNNN-NNNN
  --no-verify           Disable SSL certificate verification
  -v, --verbose         Display detailed SSVC data

Example usage:
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

$ ./vulnrich.py -id CVE-2025-22949 --no-verify
none,yes,total

$
```



# LICENSE

MIT License.

