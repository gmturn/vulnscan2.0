def Write_To_File(d_File, data):
    try:
        with open(d_File, 'w') as file:
            if isinstance(data, list):
                for item in data:
                    file.write(f"{item}\n")
    
    except:
        raise ValueError(f"Error: Could not write to file {d_File}")