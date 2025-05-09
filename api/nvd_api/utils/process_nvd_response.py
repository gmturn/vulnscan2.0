def process_nvd_response(response_data, flag, host_ip):
    """
    Processes the NVD response data and formats it into a simplified structure.

    Args:
        response_data (dict): The response data from the NVD API.
        flag (str): The type of query used (e.g., 'cve_id', 'service_name').
        host_ip (str): The host IP for which the vulnerability is being queried.

    Returns:
        dict: Simplified vulnerability data.
    """
    simplified_data = {
        'host_ip': host_ip,
        'cve_id': [],
        'vulnerabilities': []
    }

    # Handle CVE-specific data extraction
    if flag == 'cve_id':
        for item in response_data.get('CVE_Items', []):
            cve_id = item['cve']['CVE_data_meta']['ID']
            description = item['cve']['description']['description_data'][0]['value']
            cvss_score = item['impact']['baseMetricV2']['cvssV2']['baseScore']
            simplified_data['cve_id'].append(cve_id)
            simplified_data['vulnerabilities'].append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score
            })

    # Handle service or version specific queries
    elif flag in ['service_name', 'service_version']:
        for item in response_data.get('CVE_Items', []):
            cve_id = item['cve']['CVE_data_meta']['ID']
            description = item['cve']['description']['description_data'][0]['value']
            cvss_score = item['impact']['baseMetricV2']['cvssV2']['baseScore']
            simplified_data['cve_id'].append(cve_id)
            simplified_data['vulnerabilities'].append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score
            })

    # Additional logic for other flags can be added here

    return simplified_data
