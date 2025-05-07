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
        self.Arguments = self.config['Arguments']

        self.Traceroute = self.config['Traceroute']
        self.Verbose = self.config['Verbose']

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


config = return_config("config/config.conf")
myScanner = NmapScanner(config)
myScanner.LoadIPs()
