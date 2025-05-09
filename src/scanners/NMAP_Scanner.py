import nmap
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

# from utilities.u_utils import return_config  # noqa: E402
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
        self.MaxScans = int(
            self.config['MaxScans']) if self.config['MaxScans'] else None
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
        print()
        print("Launching Nmap Scan ...")

        startTime = time.time()

        self.LoadIPs()

        # [1.0] PREPARE ARGUMENTS FOR SCAN
        arguments = ""
        if self.Arguments:
            arguments += f"{self.get_arguments(self.ScanType)} {self.Arguments}"
        else:
            arguments += self.get_arguments(self.ScanType)
        if self.SaveToFile:
            arguments += " -oN data/NmapScanResults.txt"
        arguments += " --script vuln"
        if self.Traceroute:
            arguments += " --traceroute"

        # [2.0] SCAN TARGETS
        if self.MaxScans:
            self.Scanner.scan(hosts=self.format_hosts(
                self.hosts[:self.MaxScans]), arguments=arguments)
        else:
            self.Scanner.scan(hosts=self.format_hosts(
                self.hosts), arguments=arguments)

        # [3.0] RETURN NMAP SCAN RESULTS (list of m_Nmap_Result instances)
        results = []
        for host in self.Scanner.all_hosts():
            scan_result = self.Scanner[host]
            nmap_result = NmapResult(hostIP=host, n_scan_result=scan_result)

            # call NmapResult methods
            nmap_result.getAttributes()
            nmap_result.store_serialize(d_path="logs/")

            results.append(nmap_result)

        endTime = time.time()
        duration = endTime - startTime

        print(f"Nmap Scan Completed in {duration:.2f} seconds.")
        return results

    def serialize_ScanHosts(self, d_path="logs/"):
        nmapresult = NmapResult()
        result_dict = nmapresult.load_serialize()
        return result_dict
