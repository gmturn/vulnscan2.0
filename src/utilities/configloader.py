import configparser


def load_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path + "config.conf")
    return config
