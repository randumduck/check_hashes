import requests
import json
from itertools import cycle
from tabulate import tabulate

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

# Function to get Bitdefender result for a given hash
def get_bitdefender_result(hash_value, api_key):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {
        'x-apikey': api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        json_response = response.json()
        bitdefender_result = json_response['data']['attributes']['last_analysis_results']['BitDefender']
        return bitdefender_result['result']
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
    api_key = next(api_key_cycle)
    result = get_bitdefender_result(hash_value, api_key)
    results.append([hash_value, result])

# Print the results in a tabular format
print(tabulate(results, headers=["Hash", "BitDefender Result"], tablefmt="grid"))

# Save the results to a file
with open('hash_output.txt', 'w') as f:
    f.write(tabulate(results, headers=["Hash", "BitDefender Result"], tablefmt="grid"))

print("Results have been saved to hash_output.txt")
