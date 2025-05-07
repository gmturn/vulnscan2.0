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


config = return_config("config/config.conf")
myScanner = NmapScanner(config)
