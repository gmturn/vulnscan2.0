import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from models.m_Nmap_Result import NmapResult  # noqa: E402

# Parse Nmap scan result and create one NmapResult model instance


def create_NmapResult_instance(scan_result, hostIP):
    result = NmapResult(hostIP=hostIP)  # initialize model instance

    # checking and adding OS result
    if 'osmatch' in scan_result:
        result.OSInfo = scan_result['osmatch']

    # checking and adding services results
    for protocol in scan_result.all_protocols():
        print(f"Scanning protocol: {protocol}")

        open_ports = scan_result[protocol].keys()

        if not open_ports:  # If no open ports are found for this protocol, print a debug message
            print(f"No open ports found for protocol {protocol} on {hostIP}")

        for port in open_ports:
            service = scan_result[protocol][port]['name']
            version = scan_result[protocol][port].get(
                'version', 'N/A')  # get version, set fallback to 'N/A'

            # add service to the instance
            result.addService(port, service, version)

    # checking and adding vulnerabilities results
    if 'hostscript' in scan_result:
        for script in scan_result['hostscript']:
            script_name = script['id']
            script_output = script['output']

            print(f"Found script: {script_name} with output: {script_output}")

            if 'CVE' in script_output:
                CVE_ID = script_output.split()[0]
                desc = ' '.join(script_output.split()[1:])
                result.addVulnerability(CVE_ID, desc)

            else:
                print(f"No CVE found in script output: {script_output}")

    result.toDict()
    return result
