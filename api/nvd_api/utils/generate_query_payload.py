def generate_query_payload(flag, value):
    """
    Generates the appropriate query parameters based on the flag and value provided.
    """
    if flag == 'cve_id':
        # Query by CVE ID
        return f"CVE-{value}"

    elif flag == 'service_name':
        # Query by Service Name
        return f"product:{value}"

    elif flag == 'service_version':
        # Query by Service Version
        return f"version:{value}"

    elif flag == 'cvss_score':
        # Query by CVSS score
        return f"cvss:score>{value}"

    elif flag == 'cwe_id':
        # Query by CWE ID (Common Weakness Enumeration)
        return f"cwe:{value}"

    elif flag == 'published_date':
        # Query by Published Date
        return f"published:{value}"

    else:
        raise ValueError("Unsupported query flag")
