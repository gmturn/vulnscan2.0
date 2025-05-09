import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from models.m_Device import NetworkDevice  # noqa: E402


class Logger:
    def __init__(self):
        pass

    def LogARPResults(self, results, d_Path="data/"):
        if not isinstance(results, tuple):  # Error Handling
            raise TypeError(
                "Error: Could not log ARP results. Data is not a tuple.")

        f_ActiveIPs = "ActiveIPs.txt"
        f_InactiveIPs = "InactiveIPs.txt"

        # Unpackaging the results passed to the method
        Answered = results[0]
        Unanswered = results[1]

        ActiveIPs = []
        InactiveIPs = []

        # Create List of Active IPs
        for element in Answered:
            ActiveIPs.append(element[1].psrc)

        # Create List of Inactive IPs
        for element in Unanswered:
            InactiveIPs.append(element.pdst)

        write_list(d_Path + f_ActiveIPs, ActiveIPs)
        write_list(d_Path + f_InactiveIPs, InactiveIPs)

        print("ARP scan results successfully logged to:")
        print(f"\t-> {d_Path + f_ActiveIPs}")
        print(f"\t-> {d_Path + f_InactiveIPs}")

    def _LogNmapResults(self, results, d_Path="data/"):
        try:
            # create directory if it doesn't exist
            if not os.path.exists(d_Path):
                os.makedirs(d_Path)

            # convert to list of dictionaries
            results_data = []
            for result in results:
                # append the simple data
                results_data.append(result.toDict()[0])

            file_path = os.path.join(d_Path, "NmapScanResults.json")

            # Write results to JSON file
            with open(file_path, 'w') as json_file:
                json.dump(results_data, json_file, indent=4)

            print(f"Nmap scan results successfully logged to {file_path}")

        except FileNotFoundError:
            print(f"Error: The directory {d_Path} was not found.")
        except IOError as e:
            print(f"Error: Unable to write to file {d_Path}. {str(e)}")
        except json.JSONDecodeError:
            print("Error: Failed to encode data to JSON.")
        except Exception as e:
            print(f"Unexpected error occurred: {str(e)}")

    def LogNmapResults(self, results, d_Path="data/"):
        try:
            # create directory if it doesn't exist
            if not os.path.exists(d_Path):
                os.makedirs(d_Path)

            # convert to list of dictionaries
            results_data = []
            for result in results:
                # append the simple data
                results_data.append(result.toDict()[0])

            file_path = os.path.join(d_Path, "NmapScanResults.json")

            # Write results to JSON file
            with open(file_path, 'w') as json_file:
                json.dump(results_data, json_file, indent=4)

            print(f"Nmap scan results successfully logged to {file_path}")

        except FileNotFoundError:
            print(f"Error: The directory {d_Path} was not found.")
        except IOError as e:
            print(f"Error: Unable to write to file {d_Path}. {str(e)}")
        except json.JSONDecodeError:
            print("Error: Failed to encode data to JSON.")
        except Exception as e:
            print(f"Unexpected error occurred: {str(e)}")
