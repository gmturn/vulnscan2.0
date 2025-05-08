import json


class NmapResult:
    def __init__(self, hostIP, OSInfo=None, openPorts=None, services=None, vulnerabilities=None):
        # Initialize Attributes -- if None, initialize respective data types
        self.hostIP = hostIP
        self.OSInfo = OSInfo if OSInfo else {}
        self.openPorts = openPorts if openPorts else []
        self.services = services if services else []
        self.vulnerabilities = vulnerabilities if vulnerabilities else []

    def addService(self, port, service, version):
        self.services.append({
            'port': port,
            'service': service,
            'version': version
        })

    def addVulnerability(self, CVE_ID, desc):
        self.vulnerabilities.append({
            'cve_id': CVE_ID,
            'description': desc
        })

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
        return json.dumps(self.toDict(), indent=4)

    # Print Model
    def __str__(self):
        result = f"Host: {self.hostIP}\n"

        # Get the dictionary representation of the instance
        data = self.toDict()
        print(data)

        # OS information

        # Open ports and services

        # Vulnerabilities
        return ""
