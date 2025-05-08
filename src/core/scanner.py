import scapy.all as scapy
import sys
import os

from logger import Logger

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from utilities.u_utils import return_config  # noqa: E402
from scanners.ARP_Scanner import ARPScanner  # noqa: E402
from scanners.NMAP_Scanner import NmapScanner  # noqa: E402


class Scanner:
    def __init__(self, config):
        print()
        print("Initialize Network Scanner ...")

        # Initializing Attributes from Config Data Type
        self.config = config

        # ARP Attributes
        self.ARPScanner = ARPScanner(self.config)
        self.ARPResults = ()

        # Nmap Attributes
        self.NmapScanner = NmapScanner(self.config)
        self.NmapResults = []

        # Other Attributes
        self.Logger = Logger()

    def Send_ARP_Scan(self):
        self.ARPResults = self.ARPScanner.ScanNetwork()

    def Log_ARP_Results(self):
        self.Logger.LogARPResults(self.ARPResults, self.config['d_Data'])

    def Send_Nmap_Scan(self):
        self.NmapResults = self.NmapScanner.ScanHosts()

    def Log_Nmap_Results(self):
        self.Logger.LogNmapResults(self.NmapResults, d_Path="data/")


config = return_config("config/config.conf")
myScanner = Scanner(config)

myScanner.Send_ARP_Scan()
myScanner.Log_ARP_Results()

myScanner.Send_Nmap_Scan()
myScanner.Log_Nmap_Results()
