import json


class Nmap_Result:
    def __init__(self, hostIP, OSInfo=None, openPorts=None, services=None, vulnerabilities=None):
        # Initialize Attributes -- if None, initialize respective data types
        self.hostIP = hostIP
        self.OSInfo = OSInfo if OSInfo else {}
        self.openPorts = openPorts if openPorts else []
        self.services = services if services else []
        self.vulnerabilities = vulnerabilities if vulnerabilities else []

    # Convert to dictionary data type
    def toDict(self):
        d = {
            'host_ip': self.hostIP,
            'os_info': self.OSInfo,
            'open_ports': self.openPorts,
            'services': self.services,
            'vulnerabilities': self.vulnerabilities
        }
        return d

    # Convert to JSON data type
    def toJSON(self):
        return json.dumps(self.toDict(), indent=1)
