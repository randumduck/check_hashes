### Summary

This project, **VirusTotal Hash Checker**, automates the process of checking multiple hashes against VirusTotal and retrieves only Bitdefender's results. It includes two versions of the script, each with different features and functionalities.

#### Setup and Run the Script

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

#### Version 1: `check_hashes_v1.py`

- **Usage**:
  1. Prepare a file named `hashes.txt` with one hash per line.
  2. Update the script with your VirusTotal API key.
  3. Run the script:
     ```bash
     python check_hashes_v1.py
     ```

- **Features**:
  - Uses a single API key hardcoded in the script.
  - Prints results directly to the console.
  - Basic error handling for missing `hashes.txt` file.

#### Version 2: `check_hashes_v2.py`

- **Usage**:
  1. Prepare a file named `hashes.txt` with one hash per line.
  2. Create a `config.json` file with multiple API keys.
  3. Run the script:
     ```bash
     python check_hashes_v2.py
     ```

- **Features**:
  - Uses multiple API keys stored in a `config.json` file and cycles through them.
  - Prints results in a tabular format and saves them to a file.
  - Enhanced error handling for missing or malformed `config.json` file and API response errors.

#### Why Two Versions?

- **Version 1** is simpler and suitable for users who have a single API key and prefer straightforward console output.
- **Version 2** is more robust, allowing the use of multiple API keys to avoid rate limits and providing a more structured output format.

This dual-version approach ensures flexibility and caters to different user needs and preferences.
