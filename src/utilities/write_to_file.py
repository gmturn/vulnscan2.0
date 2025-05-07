def write_list(d_File, data):
    try:
        if isinstance(data, list):
            with open(d_File, 'w') as file:
                if isinstance(data, list):
                    for item in data:
                        file.write(f"{item}\n")
        else:
            raise TypeError(
                f"Error: Invalid data type being written to {d_File}")

    except:
        raise ValueError(f"Error: Could not write to file {d_File}")
