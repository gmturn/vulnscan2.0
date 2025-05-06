import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'src')))

from utilities.write_to_file import Write_To_File  # noqa: E402


file = "tests/t_data/t_IPList.txt"
list = ['192.168.1.117', '192.168.1.118', '192.168.1.119']

Write_To_File(file, list)
