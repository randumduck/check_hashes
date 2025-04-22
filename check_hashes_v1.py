import requests

# Your VirusTotal API key
api_key = 'api-key'

# Function to get Bitdefender result for a given hash
def get_bitdefender_result(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {
        'x-apikey': api_key
    }
    
    response = requests.get(url, headers=headers)
    print(f"Requesting data for hash: {hash_value}")  # Debugging statement
    
    if response.status_code == 200:
        json_response = response.json()
        bitdefender_result = json_response['data']['attributes']['last_analysis_results']['BitDefender']
        return bitdefender_result['result']
    else:
        print(f"Error: {response.status_code}")  # Debugging statement
        return f"Error: {response.status_code}"

# Read hashes from file
try:
    with open('hashes.txt', 'r') as file:
        hashes = [line.strip() for line in file]
    print("Hashes loaded successfully.")  # Debugging statement
except FileNotFoundError:
    print("Error: 'hashes.txt' file not found.")  # Debugging statement
    exit()

# Check each hash and print Bitdefender's result
for hash_value in hashes:
    result = get_bitdefender_result(hash_value)
    print(f'Hash: {hash_value}, BitDefender Result: {result}')
