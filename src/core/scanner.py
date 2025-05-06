import scapy.all as scapy
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from utilities.utils import return_config  # noqa: E402
from scanners import ARPScanner  # noqa: E402


class Scanner:
    def __init__(self, config):
        # Initializing Attributes from Config Data Type

        self.config = config
        print(self.config)
        self.ARPScanner = ARPScanner(self.config)

        # self.config = config
        # self.c_IPRange = config['DEFAULT']['IPRange']
        # self.c_HostIP = config['DEFAULT']['HostIP']
        # self.c_HostMAC = config['DEFAULT']['HostMAC']
        # self.c_Timeout = config['DEFAULT']['Timeout']
        # self.c_Verbose = config['DEFAULT']['Verbose']
        # self.c_ScanType = config['DEFAULT']['ScanType']
        # self.c_Data = config['DEFAULT']['Data']

    def Send_ARP_Request(self):
        self.ARPScanner.ScanNetwork()


config = return_config("config/config.conf")
myScanner = Scanner(config)
myScanner.Send_ARP_Request()
