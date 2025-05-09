
import requests
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'api')))

from nvd_api.utils.process_nvd_response import process_nvd_response  # noqa: E402
from nvd_api.utils.generate_query_payload import generate_query_payload  # noqa: E402


class NVD_API_Handler:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, host_ip):
        self.host_ip = host_ip

    def query_cve(self, flag, value):
        """
        Queries the NVD API and returns the formatted response.

        Args:
            flag (str): The type of query (e.g., 'cve_id', 'service_name').
            value (str): The query value (e.g., CVE ID, service version).

        Returns:
            dict: The formatted vulnerability data.
        """
        # Generate the query payload
        query_payload = generate_query_payload(flag, value)

        # Send the API request
        url = f"{self.BASE_URL}?keyword={query_payload}"
        try:
            response = requests.get(url)
            response.raise_for_status()  # Raise an error for invalid responses
            response_data = response.json()

            # Process and format the NVD response data
            formatted_data = process_nvd_response(
                response_data, flag, self.host_ip)
            return formatted_data

        except requests.exceptions.RequestException as e:
            print(f"Error querying NVD API: {e}")
            return None


if __name__ == "__main__":
    # Example host IP (you can replace this with the actual IP you're testing with)
    host_ip = "192.168.1.66"

    # Initialize the NVD_API_Handler class with the host IP
    nvd_handler = NVD_API_Handler(host_ip)

    # Example query for CVE by service version (e.g., "OpenSSH 7.9")
    flag = 'service_version'
    value = 'OpenSSH 7.9'

    # Query the NVD API
    result = nvd_handler.query_cve(flag, value)

    # Print the result
    if result:
        print("Formatted NVD Data:")
        print(result)
    else:
        print("No vulnerabilities found or error occurred.")
