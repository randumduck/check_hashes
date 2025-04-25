### Summary

This project, **VirusTotal Hash Checker**, automates the process of checking multiple hashes against VirusTotal and retrieves only Bitdefender's results. It includes four versions of the script, each with different features and functionalities.

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

#### Version 3: `check_hashes_v3.py`

- **Usage**:
  1. Prepare a file named `hashes.txt` with one hash per line.
  2. Create a `config.json` file with multiple API keys.
  3. Run the script:
     ```bash
     python check_hashes_v3.py
     ```

- **Features**:
  - Validates if the provided hash is a valid MD5, SHA1, or SHA256.
  - Checks the last analyzed date and refreshes if it's older than 2 days.
  - Retrieves the verdict from "BitDefender" (excluding "Bitdefender Falx").
  - Calculates the overall score ratio from all vendors.
  - Determines the file type.
  - Checks the file signature status.
  - Compares the file creation date vs. the first seen date.
  - Checks if the file is tracked by NSRL.
  - Looks for VT tags.

#### Version 4: `check_hashes_v3_Jira.py`

- **Usage**:
  1. Prepare a file named `hashes.txt` with one hash per line.
  2. Create a `config.json` file with multiple API keys.
  3. Run the script:
     ```bash
     python check_hashes_v3_Jira.py
     ```

- **Features**:
  - Includes all features of `check_hashes_v3.py`.
  - Generates a pipe-separated table that can be copied verbatim into Jira text mode to convert into a table in visual mode.
  - Saves the Jira-compatible table to `hash_output_jira.txt`.

### Why Four Versions?

- **Version 1** is simpler and suitable for users who have a single API key and prefer straightforward console output.
- **Version 2** is more robust, allowing the use of multiple API keys to avoid rate limits and providing a more structured output format.
- **Version 3** adds advanced features like hash validation, analysis date checks, and detailed file information.
- **Version 4** extends Version 3 by generating Jira-compatible output for easy integration into project management workflows.

This multi-version approach ensures flexibility and caters to different user needs and preferences.
