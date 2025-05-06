import configparser


def return_config(config_path):
    config = configparser.ConfigParser()
    # config.read(config_path + "config.conf")
    config.read(config_path)

    # Ensure Proper Data Types
    conf = {'IPRange': str(config['DEFAULT']['IPRange']), 'HostIP': str(config['DEFAULT']
                                                                        ['HostIP']), 'HostMAC': str(config['DEFAULT']['HostMAC']), 'Timeout': int(config['DEFAULT']['Timeout']), 'Verbose': bool(config['DEFAULT']['Verbose']), 'ScanType': str(config['DEFAULT']['ScanType']), 'Data': str(config['DEFAULT']['Data'])}

    return config
