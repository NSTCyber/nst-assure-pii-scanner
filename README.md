# NST Assure PII Scanner

NST Assure PII Scanner is an interactive Python script that scans local files, SMB shares, FTP servers, and databases for Personally Identifiable Information (PII) by matching various patterns, including Social Security Numbers, email addresses, credit card numbers, and more.

## Features

- Interactive and user-friendly
- Supports credentialed scanning
- Scans local file shares, SMB shares, FTP servers, and databases
- Searches for multiple PII patterns, including SSNs, email addresses, credit card numbers, and more

## Requirements

- Python 3.6 or later
- smbprotocol library: `pip install smbprotocol`
- pymysql library: `pip install pymysql`

## Usage

1. Clone the repository or download the script.

2. Install the required libraries:

pip install smbprotocol pymysql


3. Run the script:

python nst_assure_pii_scanner.py


4. Follow the prompts to enter the necessary credentials and information for each service (SMB, FTP, and database).

## Limitations

- The current script is a starting point and needs to be expanded with specific scanning logic for SMB, FTP, and databases.
- Uncredentialed scanning is not implemented.
- The provided PII patterns might not cover every possible type of PII.

## Disclaimer

Always ensure you have the necessary permissions before scanning any systems for PII. Unauthorized scanning may be illegal and unethical.

