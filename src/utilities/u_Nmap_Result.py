import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from models.m_Nmap_Result import NmapResult   # noqa: E402 # type: ignore


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
        osmatch = n_scan_result.get('osmatch', [])

        # Check if osmatch is empty
        if osmatch:
            os_1 = osmatch[0]
            return os_1.get('name', 'N/A')

    else:
        return 'N/A'


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
