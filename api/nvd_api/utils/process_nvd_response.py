def process_response(nvd_response, flag, hostIP=None):
    simple_result = {
        "cve_id": "",
        "published": "",
        "description": "",
        "metrics": {},
        "url": ""

    }

    if flag == 'cve_id':
        vulnerabilities = nvd_response.get("vulnerabilities", [])
        if vulnerabilities:
            d_cve = vulnerabilities[0].get("cve", {})

            # Extract and update cve_id
            cve_id = d_cve.get("id", 'N/A')
            simple_result["cve_id"] = cve_id

            # Extract and update published
            published = d_cve.get("published", "N/A")
            simple_result["published"] = published

            # Extract and update description
            l_description = d_cve.get("descriptions", [])
            if l_description:
                description = l_description[0].get("value", "N/A")
                simple_result["description"] = description

            # Extract and update metrics
            d_metrics = d_cve.get("metrics", {})
            if d_metrics:
                key, value = next(iter(d_metrics.items()))

                cvssMetricv31 = value[0]

                if cvssMetricv31:
                    attack_vector = cvssMetricv31.get(
                        "cvssData").get("attackVector", "N/A")
                    attack_complexity = cvssMetricv31.get(
                        "cvssData").get("attackComplexity", "N/A")
                    base_score = cvssMetricv31.get(
                        "cvssData").get("baseScore", -1.0)
                    base_severity = cvssMetricv31.get(
                        "cvssData").get("baseSeverity", "N/A")
                    metrics = {
                        "attackVector": attack_vector,
                        "attack_complexity": attack_complexity,
                        "baseScore": base_score,
                        "baseSeverity": base_severity
                    }
                    simple_result["metrics"] = metrics

            # Extract and update url
            l_references = d_cve.get("references", [])
            if l_references:
                url = l_references[0].get("url", "N/A")
                simple_result["url"] = url
    return simple_result
