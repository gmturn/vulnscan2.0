import nmap
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from utilities.u_utils import return_config  # noqa: E402
from models.m_Nmap_Result import NmapResult  # noqa: E402


class NmapScanner:
    def __init__(self, config):
        # Config Attributes
        self.config = config
        self.f_ActiveIPs = self.config['d_Data'] + self.config['ActiveIPs']

        self.ScanType = self.config['ScanType']
        self.Arguments = self.config['Arguments']
        self.SaveToFile = self.config['SaveToFile']
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
        # [1.0] PREPARE ARGUMENTS FOR SCAN
        # (1.1) Initialize Arguments
        arguments = ""

        # (1.2) Add arguments based on config.conf values
        if self.Arguments:
            # combine additional arguments
            arguments += f"{self.get_arguments(self.ScanType)} {self.Arguments}"
        else:
            arguments += self.get_arguments(self.ScanType)

        # (1.3) Save to .txt file if set to true
        if self.SaveToFile:
            arguments += " -oN data/NmapScanResults.txt"

        # (1.4) Scan for vulnerabilities
        arguments += " --script vuln"

        # (1.5) Traceroute if set to true
        if self.Traceroute:
            arguments += " --traceroute"

        # [2.0] SCAN TARGETS
        # (2.1) Scan hosts using given arguments
        if self.ScanLimit:
            self.Scanner.scan(hosts=self.format_hosts(
                self.hosts[:self.MaxScans]), arguments=arguments)
        else:
            self.Scanner.scan(hosts=self.hosts, arguments=arguments)

        # [3.0] RETURN NMAP SCAN RESULTS (list of m_Nmap_Result instances)


config = return_config("config/config.conf")
myScanner = NmapScanner(config)
myScanner.LoadIPs()
myScanner.ScanHosts()
