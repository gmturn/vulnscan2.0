# Network Vulnerability Scanner

## Overview

The **Network Vulnerability Scanner** is a tool suite designed to scan local networks for active devices and perform vulnerability assessments using **ARP** and **Nmap** scanning techniques. The tool integrates with the **NVD (National Vulnerability Database)** to identify known vulnerabilities based on CVEs (Common Vulnerabilities and Exposures), providing network administrators and security professionals with a comprehensive view of the security posture of machines on a network.

This tool allows you to:

- Perform **ARP scans** to discover devices on a local network.
- Use **Nmap** to scan these devices for open ports, services, and vulnerabilities.
- Query the **NVD API** for CVEs and other vulnerability-related data.
- Output the results into readable formats like JSON for further analysis and reporting.

## Installation

### Prerequisites

1. **Python 3.7+**: Ensure you have Python 3.7 or higher installed on your system.
2. **Required Libraries**: The following Python packages are required:
   - `requests`
   - `nmap`
   - `json`
   - `os`
   - `argparse`

You can install the dependencies using `pip`:

`pip install -r requirements.txt`

### Setup Instructions

1. Clone the repository to your local machine:

`git clone https://github.com/yourusername/network-vulnerability-scanner.git`

2. Navigate to the project directory:

`cd network-vulnerability-scanner`

3. Install any dependencies if you haven’t already:

`pip install -r requirements.txt`

4. Configure the project by modifying `config.conf` with your preferred scan options.

### Running the Project

Once everything is set up, you can run the main script to start scanning:

`python main.py`

You may need to modify the `config.conf` file to match your network configuration.

---

## Usage

### Running a Network Scan

To start scanning, run the following command:

`python main.py`

The tool will:

1. Perform an **ARP scan** to discover active devices on the network.
2. Perform an **Nmap scan** on the active devices to identify open ports, services, and vulnerabilities.
3. Query the **NVD API** for CVEs related to each identified service.
4. Output the results in a JSON format, which can be saved to a file for later analysis.

### Configuring Scan Parameters

- Modify the `config.conf` file to specify parameters such as:
  - IP range to scan (`IPRange`)
  - Scan type (`ScanType`): `basic`, `aggressive`, `stealth`, `os`
  - Whether to save results to a file (`SaveToFile`)

The tool will automatically use these settings to configure the scan process.

---

## Methods Overview

Here’s a list of key methods used in the project, including their purpose and how they interact with other functions.

### **1. `logger.py`**

- **`log_scan_result()`**:
  - Logs scan results into a file for future analysis. Works with `scanner.py` to save Nmap and ARP scan results.
- **`log_error()`**:
  - Logs error messages into an error log. Works with `scanner.py` to log any scan-related errors.

---

### **2. `scanner.py`**

- **`ScanHosts()`**:
  - Orchestrates the scanning process (ARP and Nmap). Configures arguments, performs scans, and returns results as `m_Nmap_Result` instances.
  - Interacts with `ARP_Scanner.py` and `NMAP_Scanner.py` to execute the scans and with `logger.py` to log results.

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
