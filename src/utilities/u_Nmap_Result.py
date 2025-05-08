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


def extract_simple_data(scan_result):
    """
    Extract simplified data from the complex scan result.
    """
    simple_data = {
        'host_ip': scan_result.get('host_ip', ''),
        'os_info': scan_result.get('os_info', {}).get('name', 'N/A'),
        'open_ports': scan_result.get('open_ports', []),
        'services': {},
        'vulnerabilities': []
    }

    for service in scan_result.get('services', []):
        simple_data['services'][service['service']] = {
            'port': service['port'],
            'version': service.get('version', 'N/A')
        }

    simple_data['vulnerabilities'] = scan_result.get('vulnerabilities', [])
    return simple_data
