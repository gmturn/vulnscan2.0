import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from models.m_Nmap_Result import NmapResult   # noqa: E402 # type: ignore
# test comment
# Parse Nmap scan result and create one NmapResult model instance


def create_NmapResult_instance(scan_result, hostIP):
    result = NmapResult(hostIP=hostIP)  # initialize model instance

    # checking and adding OS result
    if 'osmatch' in scan_result:
        result.OSInfo = scan_result['osmatch']

    # checking and adding services results
    for protocol in scan_result.all_protocols():

        open_ports = scan_result[protocol].keys()

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

            if 'CVE' in script_output:
                CVE_ID = script_output.split()[0]
                desc = ' '.join(script_output.split()[1:])
                result.addVulnerability(CVE_ID, desc)

    result.toDict()
    result.getAttributes()
    return result


def format_n_services(n_scan_result):
    if isinstance(n_scan_result, dict):
        services = {}

        # get the tcp key
        tcp = n_scan_result.get('tcp', {})

        # iterate through dictionary; for key, value in tcp.items()
        for port, port_data in tcp.items():
            service_name = port_data.get('name', 'N/A')
            service_version = port_data.get('version', 'N/A')

            # Add the formatted entry
            services[service_name] = {
                'port': port,
                'version': service_version
            }
        return services

    else:
        raise TypeError("Error: Could not format services.")


def format_n_OSInfo(n_scan_result):
    if isinstance(n_scan_result, dict):
        osmatch = n_scan_result.get('osmatch', 'N/A')
        os_1 = osmatch[0]
        return os_1.get('name', 'N/A')

    else:
        raise TypeError("Error: Could not format OSInfo.")


def extract_simple_data(scan_result):
    """
    Extract simplified data from the complex scan result.
    """
    simple_data = {
        'host_ip': scan_result.get('addresses', 'N/A').get('ipv4', 'N/A'),
        'os_info': format_n_OSInfo(scan_result),
        'open_ports': scan_result.get('open_ports', ['Functionality Not Yet Added']),
        'services': format_n_services(scan_result),
        'vulnerabilities': scan_result.get('hostscript', [])
    }

    return simple_data
