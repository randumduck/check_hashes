```markdown
# VirusTotal Hash Checker

This project automates the process of checking multiple hashes against VirusTotal and retrieves only Bitdefender's results.

## Prerequisites

- Python 3.x
- VirusTotal API key

## Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/virustotal-hash-checker.git
   cd virustotal-hash-checker
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv virustotal_env
   ```

3. **Activate the Virtual Environment**:
   - On Windows:
     ```bash
     virustotal_env\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source virustotal_env/bin/activate
     ```

4. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Version 1: `check_hashes_v1.py`

### Usage

1. **Prepare a File with Hashes**:
   Create a text file named `hashes.txt` in the project directory. Each line should contain one hash.

2. **Update the Script with Your API Key**:
   Open `check_hashes_v1.py` and replace `'YOUR_API_KEY'` with your actual VirusTotal API key.

3. **Run the Script**:
   ```bash
   python check_hashes_v1.py
   ```

### Script Details

The script reads hashes from `hashes.txt`, queries VirusTotal for each hash, and prints Bitdefender's result.

### `check_hashes_v1.py`

```python
import requests

# Your VirusTotal API key
api_key = 'YOUR_API_KEY'

# Function to get Bitdefender result for a given hash
def get_bitdefender_result(hash_value):
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

# Check each hash and print Bitdefender's result
for hash_value in hashes:
    result = get_bitdefender_result(hash_value)
    print(f'Hash: {hash_value}, BitDefender Result: {result}')
```

## Version 2: `check_hashes_v2.py`

### Usage

1. **Prepare a File with Hashes**:
   Create a text file named `hashes.txt` in the project directory. Each line should contain one hash.

2. **Create a `config.json` File**:
   Create a `config.json` file in the project directory with the following structure:
   ```json
   {
       "api_keys": [
           "your_api_key_1",
           "your_api_key_2",
           "your_api_key_3"
       ]
   }
   ```

3. **Run the Script**:
   ```bash
   python check_hashes_v2.py
   ```

### Script Details

The script reads hashes from `hashes.txt`, cycles through multiple API keys from `config.json`, queries VirusTotal for each hash, and prints Bitdefender's result in a tabular format.

### `check_hashes_v2.py`

```python
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
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
