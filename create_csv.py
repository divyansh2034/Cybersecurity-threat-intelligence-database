import pandas as pd
import numpy as np

def process_malware_data():
    # Read the CSV file
    df = pd.read_csv('malicious_phish.csv')
    
    # Take first 15000 rows
    df = df.head(15000)
    
    # Truncate URLs to fit in VARCHAR(255)
    df['url'] = df['url'].str.slice(0, 255)
    
    # Generate random severity scores between 1 and 10
    np.random.seed(42)  # for reproducibility
    df['severity'] = np.random.randint(1, 11, size=len(df))
    
    # Map type to severity ranges
    def adjust_severity(row):
        if row['type'] == 'phishing':
            return max(7, row['severity'])  # phishing sites get severity >= 7
        elif row['type'] == 'malware':
            return max(8, row['severity'])  # malware sites get severity >= 8
        elif row['type'] == 'defacement':
            return min(max(4, row['severity']), 7)  # defacement sites get severity between 4-7
        else:
            return min(3, row['severity'])  # benign sites get severity <= 3
    
    df['severity'] = df.apply(adjust_severity, axis=1)
    
    # Create incident reports for high-severity cases
    df['incident_report'] = df['severity'].apply(lambda x: 'YES' if x >= 7 else 'NO')
    
    # Save the processed data to a CSV file
    output_file = 'processed_malware_data.csv'
    df.to_csv(output_file, index=False)
    print(f"Processed data saved to {output_file}")
    
if __name__ == "__main__":
    process_malware_data()
