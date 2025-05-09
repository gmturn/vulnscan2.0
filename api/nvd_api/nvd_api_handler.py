import json
import requests
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'api')))

from nvd_api.utils.generate_query_payload import generate_query_payload  # noqa: E402
from nvd_api.utils.process_nvd_response import process_response  # noqa: E402


class NVDHandler:
    """
    A class to handle all operations related to querying the NVD API for vulnerabilities.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.session = requests.Session()

    def get_api_key(self):
        try:
            with open("api/keys/nvd_key.json", 'r') as file:
                config = json.loads(file)
                print("API Key Loaded Successfully")
                return config['api_key']

        except:
            print("Proceeding Without API Key")
            return

    def query_cve(self, flag, value, host_ip):
        query_payload = generate_query_payload(flag, value)

        api_key = self.get_api_key()

        # Make the API request to the NVD
        url = f"{self.BASE_URL}?{query_payload}"
        response = self.session.get(url)

        # Check if the response was successful
        if response.status_code == 200:
            response_data = response.json()

            # Process the response data and format it
            simplified_data = process_response(
                response_data, flag, host_ip)

            return simplified_data
        else:
            print(
                f"Error: Unable to query NVD API. Status code: {response.status_code}")
            return {}

    def log_vulnerabilities(self, vulnerabilities, output_path="data/vulnerabilities_report.json"):
        """
        Logs the vulnerabilities data to a JSON file.

        Args:
            vulnerabilities (dict): The vulnerability data to log.
            output_path (str): The path where the report will be saved.
        """
        try:
            with open(output_path, 'w') as file:
                json.dump(vulnerabilities, file, indent=4)
            print(f"Vulnerability report saved to {output_path}")
        except Exception as e:
            print(f"Error: Unable to write to file {output_path}. {str(e)}")


if __name__ == "__main__":
    nvd_handler = NVDHandler()

    print("Testing CVE ID Query:")
    cve_id_results = nvd_handler.query_cve(
        'cve_id', 'CVE-2019-1010218', '192.168.1.66')

    print(cve_id_results)
    print("-" * 50)
