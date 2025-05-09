from setuptools import setup, find_packages


def load_requirements(filename='requirements.txt'):
    with open(filename, 'r') as f:
        requirements = f.read().splitlines()
    return requirements


setup(
    name='NetworkVulnerabilityScanner',
    version='2.0',
    packages=find_packages(),
    install_requires=load_requirements()
)
