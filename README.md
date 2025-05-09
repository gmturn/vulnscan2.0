# Network Vulnerability Scanner

## Overview

The **Network Vulnerability Scanner** is a tool suite designed to scan local networks for active devices and perform vulnerability assessments using **ARP** and **Nmap** scanning techniques. This tool integrates with the **NVD (National Vulnerability Database)** (work in progress, features will be updated over time) to identify known vulnerabilities based on CVE (Common Vulnerabilities and Exposures) ID's, providing network administrators and security professionals with a comprehensive view of the security posture of machines on a network.

This tool allows you to:

- Perform **ARP scans** to discover devices on a local network.
- Use **Nmap** to scan these devices for open ports, services, operating system information, and vulnerabilities.
- Query the **NVD API** for specified CVEs.
- Output the results into readable formats like JSON for further analysis (comprehensive report generation will be added in the future).

## Installation

1. Clone the repository to your local machine:

`git clone https://github.com/gmturn/vulnscan2.0.git`

2. Navigate to the project directory:

`cd vulnscan2.0`

3. Install dependencies by running the `setup.py` file:

`python setup.py`

4. Configure the project by modifying `config.conf` with your preferred scan options.

**`config.conf` Settings and Options**

- `IPRange`: Specify the range of IPs that you want to scan
- `HostIP`: Specify the IP address of the host machine
- `HostMAC`: Specify the MAC address of the host machine
- `Timeout`: Set the timeout value for scaning operations
- `Verbose`: Set whether the scan results are verbose
- `ScanType`: _Options:_ `basic`, `stealth`, `aggressive`, `os`. These options correspond to the Nmap arguments `-sV`, `-sS`, `-A`, `-O`, respectively. This option is the base of the Nmap scan arguments.
- `Arguments`: List any additional desired Nmap arguments. _ex. `-O  --version-intensity 8`_
- `SaveToFile`: If `true`, raw Nmap scan results will be outputted to `vulnscan2.   0/data/NmapScanResults.txt`
- `Traceroute`: Specify traceroute boolean (only affects the `NmapScanResults.   txt` file if `**SaveToFile**` is enabled)
- `ScanLimit`: Toggle a limit of Nmap scans sent
- `MaxScans`: Specify the maximum hosts to be Nmap scanned
- `d_Data`: Specify the directory for output files (will have greater functionality in further updates)
- `ActiveIPs`: Specify the file name that stores active hosts to be Nmap scanned (will have greater functionality in further updates)
- `InActiveIPs`: Specify the file name that stores hosts that are non-responsive to ARP requests
- `NmapScanResults`: Specify file name to store comprehensive Nmap scan results

**Note:** it is recommended to leave all directory and file location settings unchanged.

### Running the Project

After installing the project, run `main.py`:

`python main.py`

You may need to modify the `config.conf` file to match your network configuration.

---

## Usage

### Running a Network Scan

To start scanning, run the following command:

`python main.py`

The tool will:

1. Perform an **ARP scan** to discover active devices on the network.
2. Perform an **Nmap scan** on the active devices to identify open ports, services, operating system info, and vulnerabilities.
3. Output the results in a JSON format, which can be saved to a file for later analysis.
4. User will be prompted to search the NVD (National Vulnerability Database) via inputted CVE ID (full NVD integration will be added in future updates).

## Methods Overview

The following section outlines each class and methods used, as well as how they interact with the rest of the program.

### **1. `logger.py`**

- **`LogARPResults()`**:
  - This method is passed tuple of results comprised of Active and Inactive IPs. The method then logs each IP into their respective log files.
- **`LogNmapResults()`**:
  - This method is passed Nmap scan results and defers to m_Nmap_Result.py for formatting.

---

### **2. `scanner.py`**

This file serves as a top level handler for scanning operations.

- **`Send_ARP_Scan()`**:

  - Receives results from executing `ARPScanner.ScanNetwork()`

- **`Log_ARP_Results`**:

  - Passes scan results to the logger to be logged.

- **`Send_Nmap_Scan()`**:

  - Receives results from executing `NmapScanner.ScanHosts()`

- **`Log_Nmap_Results`**:
  - Passes scan results to the logger to be logged.

---

### **3. `m_Device.py`**

- **`__init__()`**:
  - Initializes the device object with attributes such as `IP`, `MAC`, etc. Represents a network device discovered via ARP scanning.
- **`toDict()`**:
  - Converts the device object into a dictionary for easier serialization.

---

### **4. `m_Nmap_Result.py`**

- **`__init__()`**:
  - Initializes the Nmap scan result object with raw scan data and simplified attributes like `hostIP`, `OSInfo`, `openPorts`, etc.
- **`addService()`**:
  - Adds services information to the result (e.g., port, service name, version).
- **`addVulnerability()`**:
  - Adds vulnerabilities information to the result (e.g., CVE ID, description).
- **`store_serialize()`**:

  - Serializes the scan result into a file for persistence.

- **`toDict()`**:
  - Converts the Nmap result into a dictionary for easier manipulation or output.

---

### **5. `ARP_Scanner.py`**

- **`scan()`**:
  - Executes an ARP scan to discover devices on the local network. Returns a list of devices as `m_Device` objects.

---

### **6. `NMAP_Scanner.py`**

- **`scan()`**:

  - Executes an Nmap scan based on the provided arguments. Scans the devices identified by the ARP scan.

- **`get_scan_results()`**:
  - Returns the scan results, which are formatted as `m_Nmap_Result` instances.

---

### **7. `u_Nmap_Result.py`**

- **`extract_simple_data()`**:

  - Extracts and simplifies the Nmap scan results for easier analysis.

- **`format_n_services()`**:

  - Formats services from raw Nmap data into a more digestible structure.

- **`format_n_OSInfo()`**:
  - Extracts and formats operating system information from Nmap scan results.

---

### **8. `u_utils.py`**

- **`write_to_file()`**:

  - Writes formatted data to a file. Used by `logger.py` and other modules to output data.

- **`format_data()`**:
  - Formats data for consistent output (e.g., pretty-printing).

---

### **9. `write_to_file.py`**

- **`write_json()`**:

  - Converts data into JSON format and writes it to a specified file.

- **`write_text()`**:
  - Writes data as plain text for simpler outputs.

---

This `README.md` provides a quick overview of the project and a detailed breakdown of each module, making it easy to understand how the different components work together. It can be pasted directly into your `README.md` file for reference alongside your UML diagram.

Let me know if you'd like to adjust anything!
