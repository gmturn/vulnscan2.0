import nmap
import json
import os


class NmapScanner:
    def __init__(self, config):
        self.config = config

        self.Scanner = nmap.PortScanner()
        self.ScanResults = {}
