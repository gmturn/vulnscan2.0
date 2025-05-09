def generate_payload(flag, value):
    if flag == 'cve_id':
        # ex. data = CVE-2020-1234)
        return f"cveId={str(value).upper()}"

    elif flag == 'service_name':
        pass

    elif flag == 'service_version':
        pass

    elif flag == 'cvss_score':
        pass

    elif flag == 'cwe_id':
        pass

    elif flag == 'published_date':
        pass

    else:
        raise ValueError(f"Unsupported query flag: {flag}")
