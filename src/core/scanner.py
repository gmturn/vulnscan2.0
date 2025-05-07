import scapy.all as scapy
import sys
import os

from logger import Logger

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from utilities.utils import return_config  # noqa: E402
from scanners import ARP_Scanner  # noqa: E402


class Scanner:
    def __init__(self, config):
        # Initializing Attributes from Config Data Type
        self.config = config

        # ARP Attributes
        self.ARPScanner = ARP_Scanner.ARPScanner(self.config)
        self.ARPResults = ()

        # Nmap Attributes
        self.NmapScanner = ()

        # Other Attributes
        self.Logger = Logger()

    def Send_ARP_Scan(self):
        self.ARPResults = self.ARPScanner.ScanNetwork()

    def Log_ARP_Results(self):
        self.Logger.LogARPResults(self.ARPResults, self.config['d_Data'])

    def Send_Nmap_Scan(self):
        pass

    def Log_Nmap_Results(self):
        pass


config = return_config("config/config.conf")
myScanner = Scanner(config)
myScanner.Send_ARP_Scan()
myScanner.Log_ARP_Results()
