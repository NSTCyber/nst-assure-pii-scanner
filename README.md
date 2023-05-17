# NST Assure PII Scanner

NST Assure PII Scanner is an interactive Python script that scans local files, SMB shares, FTP servers, and databases for Personally Identifiable Information (PII) by matching various patterns, including Social Security Numbers, email addresses, credit card numbers, and more.

## Features

- Interactive and user-friendly
- Supports credentialed scanning
- Scans local file shares, SMB shares, FTP servers, and databases
- Searches for multiple PII patterns, including SSNs, email addresses, credit card numbers, and more

## Requirements

- Python 3.6 or later
- cffi==1.15.1
- colorama==0.4.6
- cryptography==40.0.2
- cx-Oracle==8.3.0
- greenlet==2.0.2
- mysql==0.0.3
- mysqlclient==2.1.1
- psycopg2==2.9.6
- pyasn1==0.5.0
- pycparser==2.21
- pymssql==2.2.7
- PyMySQL==1.0.3
- pyodbc==4.0.39
- pysmb==1.2.9.1
- pyspnego==0.9.0
- smbprotocol==1.10.1
- SQLAlchemy==2.0.12
- tqdm==4.65.0
- typing_extensions==4.5.0

## Usage

1. Clone the repository or download the script.

2. Install the required libraries:

pip install -r requirements.txt

3. Run the script:

python assure-pii.py

4. Follow the prompts to enter the necessary credentials and information for each service (SMB, FTP, and database).
The user will be prompted for the following inputs and please enter the appropriate information,
•	"Please choose the scanning type:"
    o	Enter either "1" or "2" to select the type of scan.
    o	For Credentialed scan choose "1" or  choose "2" for Uncredentialed scan.
For Credentialed Scan, use the following options,
•	"Enter the username:"
    o	Enter the username for the credentialed scan.
•	"Enter the password:"
    o	Enter the password for the credentialed scan. The password will not be displayed as you type.
•	"Enter the path to fileshare:"
    o	Enter the path to the file share you want to scan. For example, "C:\Users\John\Documents".
•	"Enter the SMB host:"
    o	Enter the IP address or hostname of the SMB server you want to scan.
•	"Enter the SMB domain:"
    o	Enter the domain for the SMB server, if applicable. Otherwise, leave this field blank and press Enter.
•	"Enter the SMB username:"
    o	Enter the username for the SMB server.
•	"Enter the SMB password:"
    o	Enter the password for the SMB server. The password will not be displayed as you type.
•	"Enter the FTP host:"
    o	Enter the IP address or hostname of the FTP server you want to scan.
•	"Enter the FTP username:"
    o	Enter the username for the FTP server.
•	"Enter the FTP password:"
    o	Enter the password for the FTP server. The password will not be displayed as you type.
•	"Enter the database type(mysql,mssql,postgresql,oracledb):"
    o	Enter the type of database you want to scan. Valid options are "mysql", "mssql", "postgresql", or "oracledb".
•	"Enter the database host:"
    o	Enter the IP address or hostname of the database server you want to scan.
•	"Enter the database port:"
    o	Enter the port number on which the database server is listening. The default port number for each database type is:
        *	mysql: 3306
        *	mssql: 1433
        *	postgresql: 5432
        *	oracledb: 1521
•	"Enter the database username:"
    o	Enter the username for the database server.
•	"Enter the database password:"
    o	Enter the password for the database server. The password will not be displayed as you type.
Once all input prompts have been answered, the program will begin the uncredentialed scans.

For Uncredentialed Scan, use the following options,
•	"Enter the path to fileshare: "
    o	Enter the full path to the directory or fileshare you want to scan. For example, on Windows, this might be something like "C:\Users\Public\Documents".
•	"Enter the SMB host: "
    o	Enter the IP address or hostname of the SMB server you want to scan.
•	"Enter the FTP host: "
    o	Enter the IP address or hostname of the FTP server you want to scan.
•	"Enter the database type(mysql,mssql,postgresql,oracledb): "
    o	Enter the type of database you want to scan. Valid options are "mysql", "mssql", "postgresql", and "oracledb".
•	"Enter the database host: "
    o	Enter the IP address or hostname of the database server you want to scan.
•	"Enter the database port: "
    o	Enter the port number on which the database server is listening. The default port number for each database type is:
        *	mysql: 3306
        *	mssql: 1433
        *	postgresql: 5432
        *	oracledb: 1521
Once all input prompts have been answered, the program will begin the uncredentialed scans.
Note: These scans will not require any authentication, so they may not be as comprehensive as the credentialed scans.

## Limitations

- The current script is a starting point and needs to be expanded with specific scanning logic for SMB, FTP, and databases.
- Uncredentialed scanning is may not perform an exhaustive search.
- The provided PII patterns might not cover every possible type of PII.

## Disclaimer

Always ensure you have the necessary permissions before scanning any systems for PII. Unauthorized scanning may be illegal and unethical.

