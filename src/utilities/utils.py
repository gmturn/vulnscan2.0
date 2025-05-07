import configparser


def return_config(config_path):

    try:
        config = configparser.ConfigParser()
        config.read(config_path)

        # Ensure Proper Data Types
        conf = {'IPRange': str(config['DEFAULT']['IPRange']), 'HostIP': str(config['DEFAULT']
                                                                            ['HostIP']), 'HostMAC': str(config['DEFAULT']['HostMAC']), 'Timeout': int(config['DEFAULT']['Timeout']), 'Verbose': bool(config['DEFAULT']['Verbose']), 'ScanType': str(config['DEFAULT']['ScanType']), 'd_Data': str(config['DEFAULT']['d_Data']), 'ActiveIPs': str(config['DEFAULT']['ActiveIPs']), 'InactiveIPs': str(config['DEFAULT']['InactiveIPs']), 'NmapScanResults': str(config['DEFAULT']['NmapScanResults'])}
        return conf
    except:
        raise ValueError(f"Error: Could not load config file '{config_path}'")
