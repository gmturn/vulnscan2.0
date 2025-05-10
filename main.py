from src.core.scanner import Scanner
from src.utilities.u_utils import return_config
from api.nvd_api.nvd_api_handler import NVDHandler


def cve_lookup(cve_id):
    print()

    while cve_id != "0":
        nvd_handler = NVDHandler()
        result = nvd_handler.query_cve(
            'cve_id', cve_id)

        if not result:
            print()
            cve_id = str(input(
                "Enter a CVE ID to query from NVD (enter '0' to quit) \t||\tEx: CVE-2023-31702\n"))

        else:
            # Display CVE data
            print()
            print("CVE ID Query Results:")

            print("CVE ID:", result["cve_id"] if result["cve_id"] else "N/A")
            print("Published Date:", result["published"]
                  if result["published"] else "N/A")
            print("Description:", result["description"]
                  if result["description"] else "N/A")

            # Print the metrics dictionary
            if result["metrics"]:
                print("Metrics:")
                for key, value in result["metrics"].items():
                    print(f"  {key}: {value}")
            else:
                print("Metrics: N/A")

            print("URL:", result["url"] if result["url"] else "N/A")
            print("-" * 50)
            print()
            cve_id = str(input(
                "Enter a CVE ID to query from NVD (enter '0' to quit) \t||\tEx: CVE-2023-31702\n"))

    print()
    print("Program End")


if __name__ == "__main__":
    config = return_config("config/config.conf")
    myScanner = Scanner(config)

    myScanner.Send_ARP_Scan()
    myScanner.Log_ARP_Results()

    myScanner.Send_Nmap_Scan()
    myScanner.Log_Nmap_Results()

    print()
    print("Initiating CVE Lookup")
    nvd_handler = NVDHandler()

    cveID = str(input(
        "Enter a CVE ID to query from NVD (enter '0' to quit) \t||\tEx: CVE-2023-31702\n"))

    cve_lookup(cveID)
