import json


class NmapResult:
    def __init__(self, hostIP=None, n_scan_result=None):
        # NOTE -- the n_ variable modifier is used to represent the full 'n'map scan data as opposed to the simple values that are extracted

        self.n_scan_result = n_scan_result if n_scan_result else {}

        # Simple attributes - these will be derived from n_scan_result
        self.hostIP = ""
        self.OSInfo = ""
        self.openPorts = []
        self.services = {}
        self.vulnerabilities = []

        # Used to indicate whether the instance was loaded from a serialization or a real-time scan
        self.b_is_serialized = False

    def store_serialize(self, f_path="serialize/nmap.txt"):
        """ Store the raw scan result into a file as JSON """
        data = self.toDict()  # Get data as a list of 2 dictionaries
        with open(f_path, 'w') as file:
            file.write(json.dumps(data, indent=4))

    def load_serialize(self, f_path="serialize/nmap.txt"):
        """ Load the raw scan result from a serialized file """
        try:
            with open(f_path, 'r') as file:
                data = file.read()  # Read the file contents
                # Deserialize into the complex scan result
                self.n_scan_result = json.loads(data)
                self.b_is_serialized = True  # Mark that data is loaded from a serialized file
                self.getAttributes()  # Simplify the data for easy access
                return self.n_scan_result

        except FileNotFoundError:
            print(f"Error: The file at {f_path} was not found.")
            return {}
        except json.JSONDecodeError:
            print("Error: Failed to decode the JSON data.")
            return {}

    def addService(self, service_data):
        """ Adds a service to the NmapResult's simplified services data """
        self.services[service_data['service']] = {
            'port': service_data['port'],
            'version': service_data['version']
        }

    def addVulnerability(self, CVE_ID, desc):
        """ Adds a vulnerability to the NmapResult's simplified vulnerabilities data """
        self.vulnerabilities.append({
            'cve_id': CVE_ID,
            'description': desc
        })

    # Convert to dictionary data type
    # list[0] = dictionary of simple data
    # list[1] = dictionary of complex data -- unchanged data returned by the nmap scan
    def toDict(self):
        simple_data = {
            'host_ip': self.hostIP,
            'os_info': self.OSInfo,
            'open_ports': self.openPorts,
            'services': self.openPorts,
            'vulnerabilities': self.vulnerabilities
        }

        complex_data = {
            'n_scan_result': self.n_scan_result
        }

        # Return a list that contains the simple scan data, and the complex scan data
        return [simple_data, complex_data]

    # Convert to JSON data type
    def toJSON(self):
        # Return a JSON string comprised of the simple and complex scan data
        return json.dumps(self.toDict(), indent=4)

    def getAttributes(self):
        # Simplify complex data by calling on u_Nmap_Result
        if self.n_scan_result:
            # import function only if called on
            from utilities.u_Nmap_Result import extract_simple_data
            simplified_data = extract_simple_data(self.n_scan_result)

            # Set simple attributes
            self.hostIP = simplified_data['host_ip']
            self.OSInfo = simplified_data['os_info']
            self.openPorts = simplified_data['open_ports']
            self.services = simplified_data['services']
            self.vulnerabilities = simplified_data['vulnerabilities']

    # Print Model

    def __str__(self):
        """ Return a human-readable string representation of the NmapResult """
        return f"Host IP: {self.hostIP}\nOS Info: {self.OSInfo}\nServices: {self.services}\nVulnerabilities: {self.vulnerabilities}"
