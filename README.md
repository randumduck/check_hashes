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



## Version 3: `check_hashes_v3.py`

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
   python check_hashes_v3.py
   ```

### Script Details

The script includes additional features:
- Validates if the provided hash is a valid MD5, SHA1, or SHA256.
- Checks the last analyzed date and refreshes if it's older than 2 days.
- Retrieves the verdict from "BitDefender" (excluding "Bitdefender Falx").
- Calculates the overall score ratio from all vendors.
- Determines the file type.
- Checks the file signature status.
- Compares the file creation date vs. the first seen date.
- Checks if the file is tracked by NSRL.
- Looks for VT tags.

### `check_hashes_v3.py`

```python
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
```

## Version 4: `check_hashes_v3_Jira.py`

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
   python check_hashes_v3_Jira.py
   ```

### Script Details

This version includes all the features of `check_hashes_v3.py` and additionally generates a pipe-separated table that can be copied verbatim into Jira text mode to convert into a table in visual mode.

### Example Output

The script prints the results in a tabular format and saves them to `hash_output.txt`. It also generates a Jira-compatible table and saves it to `hash_output_jira.txt`.

### `check_hashes_v3_Jira.py`

```python
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
            if response.status_code

```
## License

This project is licensed under the MIT License. See the LICENSE file for details.

