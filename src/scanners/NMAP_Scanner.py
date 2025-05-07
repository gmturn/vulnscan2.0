import nmap
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from utilities.utils import return_config  # noqa: E402


class NmapScanner:
    def __init__(self, config):
        # Config Attributes
        self.config = config
        self.f_ActiveIPs = self.config['d_Data'] + self.config['ActiveIPs']

        self.ScanType = self.config['ScanType']
        self.Arguments = self.config['Arguments']
        self.ScanLimit = self.config['ScanLimit']
        self.MaxScans = self.config['MaxScans']
        self.Traceroute = self.config['Traceroute']
        self.Verbose = self.config['Verbose']

        # Nmap Attributes
        self.Scanner = nmap.PortScanner()
        self.ScanResults = {}

        self.hosts = []

    def LoadIPs(self):
        try:
            with open(self.f_ActiveIPs, 'r') as f:
                for line in f:
                    self.hosts.append(line.strip())
        except:
            raise ValueError(
                f"Error: Could not load IPs from {self.f_ActiveIPs}")

    # static method to convert scan type into arguments
    @staticmethod
    def get_arguments(scan_type):
        scan_options = {
            'basic': '-sV',
            'stealth': '-sS',
            'aggressive': '-A',
            'os': '-O'
        }
        # Default to 'basic' if scan_type is unknown
        return scan_options.get(scan_type, '-sV')

    # Static method to format data from a list
    @staticmethod
    def format_hosts(hosts):
        return ' '.join(hosts)

    def ScanHosts(self):
        # Prepare Arguments
        arguments = ""
        if self.Arguments:
            # combine additional arguments
            arguments = f"{self.get_arguments(self.ScanType)} {self.Arguments}"
        else:
            arguments = self.get_arguments(self.ScanType)
        if self.Traceroute:
            arguments += " --traceroute"

        # Scan hosts using given arguments
        if self.ScanLimit:
            self.Scanner.scan(hosts=self.format_hosts(
                self.hosts[:self.MaxScans]), arguments=arguments)
        else:
            self.Scanner.scan(hosts=self.hosts, arguments=arguments)

        # TEST
        for host in self.Scanner.all_hosts():
            host_info = {
                'state': self.Scanner[host].state(),
                'hostnames': self.Scanner[host].hostnames(),
                'protocols': self.Scanner[host].all_protocols()
            }
            print(host_info)


config = return_config("config/config.conf")
myScanner = NmapScanner(config)
myScanner.LoadIPs()
myScanner.ScanHosts()
