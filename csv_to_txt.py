import pandas as pd
import os

def csv_to_txt(csv_file, txt_file, delimiter="\t"):
    """
    Converts a CSV file to a TXT file.
    
    :param csv_file: Path to the input CSV file.
    :param txt_file: Path to the output TXT file.
    :param delimiter: Delimiter to use in the TXT file (default is tab).
    """
    try:
        # Check if the CSV file exists
        if not os.path.exists(csv_file):
            print(f"Error: CSV file '{csv_file}' not found!")
            return
        
        # Read the CSV file
        df = pd.read_csv(csv_file)
        
        # Save as a TXT file with the chosen delimiter
        df.to_csv(txt_file, sep=delimiter, index=False, header=True)
        
        print(f"Conversion successful! TXT file saved at: {txt_file}")
    except Exception as e:
        print(f"Error occurred: {e}")

# File paths
csv_file = "/Users/dhruvloriya/Desktop/DBMS EL/processed_malware_data.csv"
txt_file = "/Users/dhruvloriya/Desktop/DBMS EL/prs_mal_data.txt"

# Convert CSV to TXT
csv_to_txt(csv_file, txt_file)