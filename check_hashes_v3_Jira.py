import requests
import json
from itertools import cycle
from tabulate import tabulate
import re
from datetime import datetime, timedelta

# Load API keys from config.json
try:
    with open('config.json', 'r') as f:
        config = json.load(f)
        api_keys = config['api_keys']
except json.JSONDecodeError:
    print("Error: 'config.json' file is empty or not formatted correctly.")
    exit()
except FileNotFoundError:
    print("Error: 'config.json' file not found.")
    exit()

# Function to validate hash
def is_valid_hash(hash_value):
    if re.match(r'^[a-fA-F0-9]{32}$', hash_value):  # MD5
        return True
    elif re.match(r'^[a-fA-F0-9]{40}$', hash_value):  # SHA1
        return True
    elif re.match(r'^[a-fA-F0-9]{64}$', hash_value):  # SHA256
        return True
    else:
        return False

# Function to get Bitdefender result for a given hash
def get_bitdefender_result(hash_value, api_key):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {
        'x-apikey': api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        json_response = response.json()
        attributes = json_response['data']['attributes']
        
        # Check last analyzed date
        last_analysis_date = datetime.fromtimestamp(attributes['last_analysis_date'])
        if datetime.now() - last_analysis_date > timedelta(days=2):
            # Refresh analysis
            response = requests.post(url + '/analyse', headers=headers)
            if response.status_code != 200:
                return f"Error refreshing analysis: {response.status_code}"
        
        # Get Bitdefender result
        bitdefender_result = attributes['last_analysis_results'].get('BitDefender', {}).get('result', 'No result')
        
        # Calculate overall score ratio
        total_vendors = len(attributes['last_analysis_results'])
        positive_detections = sum(1 for result in attributes['last_analysis_results'].values() if result['category'] == 'malicious')
        score_ratio = f"{positive_detections}/{total_vendors}"
        
        # Get file type
        file_type = attributes.get('type_description', 'Unknown')
        
        # Check file signature status
        signature_info = attributes.get('signature_info', {})
        signature_status = signature_info.get('validity', 'Unknown')
        
        # Compare file creation date vs. first seen date
        creation_date = attributes.get('creation_date', 'Unknown')
        first_seen_date = attributes.get('first_submission_date', 'Unknown')
        
        # Check if file is tracked by NSRL
        nsrl = attributes.get('nsrl', False)
        
        # Get VT tags
        tags = attributes.get('tags', [])
        
        return {
            'BitDefender Result': bitdefender_result,
            'Score Ratio': score_ratio,
            'File Type': file_type,
            'Signature Status': signature_status,
            'Creation Date': creation_date,
            'First Seen Date': first_seen_date,
            'NSRL': nsrl,
            'Tags': tags
        }
    else:
        return f"Error: {response.status_code}"

# Read hashes from file
try:
    with open('hashes.txt', 'r') as file:
        hashes = [line.strip() for line in file]
except FileNotFoundError:
    print("Error: 'hashes.txt' file not found.")
    exit()

# Prepare the results in a list of lists for tabulation
results = []
api_key_cycle = cycle(api_keys)  # Cycle through API keys

for hash_value in hashes:
    if not is_valid_hash(hash_value):
        results.append([hash_value, 'Invalid hash'])
        continue
    
    api_key = next(api_key_cycle)
    result = get_bitdefender_result(hash_value, api_key)
    if isinstance(result, dict):
        results.append([
            hash_value,
            result['BitDefender Result'],
            result['Score Ratio'],
            result['File Type'],
            result['Signature Status'],
            result['Creation Date'],
            result['First Seen Date'],
            result['NSRL'],
            ', '.join(result['Tags'])
        ])
    else:
        results.append([hash_value, result])

# Print the results in a tabular format
print(tabulate(results, headers=[
    "Hash", "BitDefender Result", "Score Ratio", "File Type", "Signature Status",
    "Creation Date", "First Seen Date", "NSRL", "Tags"
], tablefmt="grid"))

# Save the results to a file
with open('hash_output.txt', 'w') as f:
    f.write(tabulate(results, headers=[
        "Hash", "BitDefender Result", "Score Ratio", "File Type", "Signature Status",
        "Creation Date", "First Seen Date", "NSRL", "Tags"
    ], tablefmt="grid"))

print("Results have been saved to hash_output.txt")

# Generate pipe-separated table for Jira
jira_table = []
jira_table.append("| Hash | BitDefender Result | Score Ratio | File Type | Signature Status | Creation Date | First Seen Date | NSRL | Tags |")
jira_table.append("|------|--------------------|-------------|-----------|------------------|----------------|-----------------|------|------|")

for result in results:
    # Ensure each column is properly formatted and spaced
    formatted_result = [str(item).replace('\n', ' ') for item in result]
    jira_table.append(f"| {' | '.join(formatted_result)} |")

jira_table_str = "\n".join(jira_table)

# Print the Jira table to the console
print("\nJira Table:\n")
print(jira_table_str)

# Save the Jira table to a file
with open('hash_output_jira.txt', 'w') as f:
    f.write(jira_table_str)

print("Jira table has been saved to hash_output_jira.txt")
