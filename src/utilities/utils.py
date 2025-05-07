import configparser


# helper function
def str_to_bool(value):
    return value.lower() in ['true', '1', 'yes']


def return_config(config_path):
    try:
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(config_path)

        # Load and convert values with correct data types
        d = 'DEFAULT'

        conf = {
            'IPRange': config.get(d, 'IPRange'),
            'HostIP': config.get(d, 'HostIP'),
            'HostMAC': config.get(d, 'HostMAC'),
            'Timeout': config.getint(d, 'Timeout'),
            'Verbose': str_to_bool(config.get(d, 'Verbose')),
            'ScanType': config.get(d, 'ScanType'),
            'Arguments': config.get(d, 'Arguments', fallback=''),
            'Traceroute': str_to_bool(config.get(d, 'Traceroute')),
            'd_Data': config.get(d, 'd_Data'),
            'ActiveIPs': config.get(d, 'ActiveIPs'),
            'InactiveIPs': config.get(d, 'InactiveIPs'),
            'NmapScanResults': config.get(d, 'NmapScanResults')
        }

        return conf
    except Exception as e:
        raise ValueError(
            f"Error: Could not load config file '{config_path}' - {str(e)}")
