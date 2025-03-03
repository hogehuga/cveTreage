# Format output
def format_output(data, format_type, mission_well_being=None, verbose=False):
    if format_type == "csv":
        output = ""
        for row in data:
            output += ",".join(row) + "\n"
        return output
    elif format_type == "tsv":
        output = ""
        for row in data:
            output += "\t".join(row) + "\n"
        return output
    else:
        # Default is table format
        if verbose:
            if mission_well_being:
                output = "|CVE-ID         |Severity|Score|Outcome|Exploitation|Automatable|Technical Impact|Mission & Well-being|CVSS Vector String                           |Source|EPSS        |EPSS(%)     |\n"
                output += "|---------------|--------|-----|-------|------------|-----------|----------------|--------------------|---------------------------------------------|------|------------|------------|\n"
                for row in data:
                    output += f"|{row[0]:<15}|{row[1]:<8}|{row[2]:<5}|{row[3]:<7}|{row[4]:<12}|{row[5]:<11}|{row[6]:<16}|{row[7]:<20}|{row[8]:<45}|{row[9]:<6}|{row[10]:<12}|{row[11]:<12}|\n"
            else:
                output = "|CVE-ID         |Severity|Score|Outcome           |Exploitation|Automatable|Technical Impact|CVSS Vector String                           |Source|EPSS        |EPSS(%)     |\n"
                output += "|---------------|--------|-----|------------------|------------|-----------|----------------|---------------------------------------------|------|------------|------------|\n"
                for row in data:
                    output += f"|{row[0]:<15}|{row[1]:<8}|{row[2]:<5}|{row[3]:<18}|{row[4]:<12}|{row[5]:<11}|{row[6]:<16}|{row[7]:<45}|{row[8]:<6}|{row[9]:<12}|{row[10]:<12}|\n"
        else:
            if mission_well_being:
                output = "|CVE-ID         |Outcome|Exploitation|Automatable|Technical Impact|Mission & Well-being|\n"
                output += "|---------------|-------|------------|-----------|----------------|--------------------|\n"
                for row in data:
                    output += f"|{row[0]:<15}|{row[1]:<7}|{row[2]:<12}|{row[3]:<11}|{row[4]:<16}|{row[5]:<20}|\n"
            else:
                output = "|CVE-ID         |Outcome           |Exploitation|Automatable|Technical Impact|\n"
                output += "|---------------|------------------|------------|-----------|----------------|\n"
                for row in data:
                    output += f"|{row[0]:<15}|{row[1]:<18}|{row[2]:<12}|{row[3]:<11}|{row[4]:<16}|\n"
        return output
