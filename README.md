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

## Usage

1. **Prepare a File with Hashes**:
   Create a text file named `hashes.txt` in the project directory. Each line should contain one hash.

2. **Update the Script with Your API Key**:
   Open `check_hashes.py` and replace `'YOUR_API_KEY'` with your actual VirusTotal API key.

3. **Run the Script**:
   ```bash
   python check_hashes.py
   ```

## Script Details

The script reads hashes from `hashes.txt`, queries VirusTotal for each hash, and prints Bitdefender's result.

### `check_hashes.py`

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

## License

This project is licensed under the MIT License. See the LICENSE file for details.
