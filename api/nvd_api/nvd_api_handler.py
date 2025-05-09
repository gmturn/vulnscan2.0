import requests
import sys
import os
import configparser

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'api')))

from nvd_api.utils.generate_query_payload import generate_query_payload  # noqa: E402
from nvd_api.utils.process_nvd_response import process_response  # noqa: E402


class NVDHandler:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        self.session = requests.Session()

    def get_api_key(self):
        try:
            f_path = 'api/nvd_api/keys/nvd_key.conf'
            config = configparser.ConfigParser()
            config.read(f_path)

            try:
                api_key = config.get('DEFAULT', 'API_KEY')
            except:
                print(
                    f"Could Not Load API Key: ensure proper data in '{f_path}'")

            if api_key:
                print("API Key Loaded Successfully")
                return api_key

        except:
            print("Proceeding Without API Key")
            return None

    def query_cve(self, flag, value, host_ip):
        query_payload = generate_query_payload(flag, value)

        api_key = self.get_api_key()

        # Make the API request to the NVD
        header = {"X-API-Key": api_key}
        url = f"{self.BASE_URL}?{query_payload}"

        response = self.session.get(url, headers=header)

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


if __name__ == "__main__":
    nvd_handler = NVDHandler()

    print("Testing CVE ID Query:")
    cve_id_results = nvd_handler.query_cve(
        'cve_id', 'cve-2012-1182', '192.168.1.66')

    print(cve_id_results)
    print("-" * 50)
