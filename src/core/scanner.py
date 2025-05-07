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
        self.ARPScanner = ARP_Scanner.ARPScanner(self.config)
        self.Logger = Logger()
        self.ARPResults = ()

    def Send_ARP_Request(self):
        self.ARPResults = self.ARPScanner.ScanNetwork()

    def Log_Results(self, d_Path="data/"):
        self.Logger.LogARPResults(self.ARPResults)


config = return_config("config/config.conf")
myScanner = Scanner(config)
myScanner.Send_ARP_Request()
myScanner.Log_Results()
