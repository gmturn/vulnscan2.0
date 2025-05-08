import json


class NmapResult:
    def __init__(self, hostIP=None, OSInfo=None, openPorts=None, services=None, vulnerabilities=None):
        # NOTE -- the n_ variable modifier is used to represent the full 'n'map scan data as opposed to the simple values that are extracted

        # Initialize Attributes -- if None, initialize respective data types
        self.n_hostIP = hostIP if hostIP else ""
        self.n_OSInfo = OSInfo if OSInfo else {}
        self.n_openPorts = openPorts if openPorts else []
        self.n_services = services if services else []
        self.n_vulnerabilities = vulnerabilities if vulnerabilities else []

        # String values used to give single string values instead of complex dictionaries
        self.hostIP = ""
        self.OSInfo = ""
        self.openPorts = []
        self.services = {}
        self.vulnerabilities = []

    def addService(self, port, service, version):
        self.n_services.append({
            'port': port,
            'service': service,
            'version': version
        })

    def store_serialize(self, f_path="serialize/nmap.txt"):
        data = self.toDict()
        with open(f_path, 'w') as file:
            file.write(str(data))

    def load_serialize(self, f_path="serialize/nmap.txt"):
        try:
            with open(f_path, 'r') as file:
                data = file.read()  # Read the file contents
                # Deserialize the data into a dictionary
                # Convert the JSON string into a Python dictionary
                # replace all single quotes with double quotes to properly load json data
                data = data.replace("'", '"')
                data_dict = json.loads(data)
                return data_dict

        except FileNotFoundError:
            print(f"Error: The file at {f_path} was not found.")
            return {}
        except json.JSONDecodeError:
            print("Error: Failed to decode the JSON data.")
            return {}

    def addVulnerability(self, CVE_ID, desc):
        self.n_vulnerabilities.append({
            'cve_id': CVE_ID,
            'description': desc
        })

    # Convert to dictionary data type
    def toDict(self):
        d = {
            'host_ip': self.n_hostIP,
            'os_info': self.n_OSInfo,
            'open_ports': self.n_openPorts,
            'services': self.n_services,
            'vulnerabilities': self.n_vulnerabilities
        }
        return d

    # Convert to JSON data type
    def toJSON(self):
        return json.dumps(self.toDict(), indent=4)

    def getAttributes(self):
        data = self.toDict()

        self.hostIP = f"{self.n_hostIP}"
        self.OSInfo = {data.get('os_info', []).get('name', 'N/A')}

        for service in data.get('services', []):
            if isinstance(service, dict):
                self.services[service.get('service')] = {
                    'port': service.get('port', 'N/A'), 'version': service.get('version', 'N/A')}

        self.vulnerabilities = data.get('vulnerabilities')

        print()
        print(self.services)

    # Print Model

    def __str__(self):
        data = self.toDict()
        print(data)

        result = ""
        s_hostIP = f"Host IP: {self.n_hostIP}\n"

        # OS information
        s_OSInfo = f"OS Info: {data.get('os_info')[0].get('name')}\n"

        # Open ports and services

        # Vulnerabilities
        return ""
