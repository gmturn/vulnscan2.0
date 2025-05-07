import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from models.Device import NetworkDevice  # noqa: E402
from utilities.write_to_file import *  # noqa: E402


class Logger:
    def __init__(self):
        pass

    def LogARPResults(self, results, d_Path="data/"):
        if not isinstance(results, tuple):  # Error Handling
            raise TypeError(
                "Error: Could not log ARP results. Data is not a tuple.")

        # Unpackaging the results passed to the method
        Answered = results[0]
        Unanswered = results[1]

        ActiveIPs = []
        InactiveIPs = []

        # Create List of Active IPs
        for element in Answered:
            ActiveIPs.append(element[1].psrc)

            # device = NetworkDevice(
            #     ipAddr=element[1].psrc, macAddr=element[1].hwsrc)
            # ActiveIPs.append(device)

        # Create List of Inactive IPs
        for element in Unanswered:
            InactiveIPs.append(element.pdst)

        write_list(d_Path + "ActiveIPs.txt", ActiveIPs)
        write_list(d_Path + "InactiveIPs.txt", InactiveIPs)
