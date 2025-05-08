import scapy.all as scapy
import os
from models.m_Device import NetworkDevice

# This class is used to send and receive ARP packets and return the results to the main scanner


class ARPScanner:
    def __init__(self, config):
        # Define necessary attributes to send ARP requests
        self.config = config
        self.IPRange = self.config['IPRange']
        self.HostIP = self.config['HostIP']
        self.HostMAC = self.config['HostMAC']
        self.Timeout = self.config['Timeout']
        self.d_Data = self.config['d_Data']

        self.ARPResults = ()

        # Initialize lists to store responses from IP addresses
        self.ActiveIPs = []
        self.InactiveIPs = []

    def ScanNetwork(self):
        print("Launching ARP Scan ...")
        request = scapy.ARP(pdst=self.IPRange)  # create ARP request packet
        broadcast = scapy.Ether(dst=self.HostMAC)  # create ethernet frame

        # combine packets into one ethernet frame
        request_broadcast = broadcast / request

        # Send ARP Request
        ARP_Responses = scapy.srp(request_broadcast, timeout=self.Timeout)

        # Categorizing Results (returned in a scapy data type and must be formatted)
        Answered = ARP_Responses[0]
        Unanswered = ARP_Responses[1]

        # return the scapy data type to be dealt with later in logger.py
        self.ARPResults = (Answered, Unanswered)

        # Create List of Active IPs
        for element in Answered:
            device = NetworkDevice(
                ipAddr=element[1].psrc, macAddr=element[1].hwsrc)
            self.ActiveIPs.append(device)

        # Create List of Inactive IPs
        for element in Unanswered:
            self.InactiveIPs.append(element.pdst)

        print("ARP Scan Complete.")
        return self.ARPResults
