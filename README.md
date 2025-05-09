# Network Vulnerability Scanner

## Overview

The **Network Vulnerability Scanner** is a tool suite designed to scan local networks for active devices and perform vulnerability assessments using **ARP** and **Nmap** scanning techniques. The tool integrates with the **NVD (National Vulnerability Database)** to identify known vulnerabilities based on CVEs (Common Vulnerabilities and Exposures), providing network administrators and security professionals with a comprehensive view of the security posture of machines on a network.

This tool allows you to:

- Perform **ARP scans** to discover devices on a local network.
- Use **Nmap** to scan these devices for open ports, services, operating system information, and vulnerabilities.
- Query the **NVD** for CVEs and other vulnerability-related data.
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

```bash
pip install -r requirements.txt
```
