import scapy.all as scapy
import os

# This class is used to send and receive ARP packets and return the results to the main scanner


class ARPScanner:
    def __init__(self, config):
        # Define necessary attributes to send ARP requests
        self.config = config
        print(type(config))
        self.IPRange = self.config['IPRange']
        self.HostIP = self.config['HostIP']
        self.HostMAC = self.config['HostMAC']
        self.Timeout = self.config['Timeout']

        # self.IPRange = config['DEFAULT']['IPRange']
        # self.HostIP = config['DEFAULT']['HostIP']
        # self.HostMAC = config['DEFAULT']['HostMAC']
        # self.Timeout = config['DEFAULT']['Timeout']

    def ScanNetwork(self, save_to_file=True):
        request = scapy.ARP(pdst=self.IPRange)  # create ARP request packet
        broadcast = scapy.Ether(dst=self.HostMAC)  # create ethernet frame

        # combine packets into one ethernet frame
        request_broadcast = broadcast / request

        # Send ARP Request
        ARP_Responses = scapy.srp(request_broadcast, timeout=self.Timeout)

        # Retrieving IP Lists based on response
        ActiveIPs = ARP_Responses[0]
        InactiveIPs = ARP_Responses[1]

        print(ActiveIPs)
