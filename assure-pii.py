import os
import re
import socket
import ftplib
import getpass
from smb.SMBConnection import SMBConnection
import pymysql

# Define PII patterns
pii_patterns = [
    r'\d{3}-\d{2}-\d{4}',  # SSN
    r'\w+@\w+\.\w+',  # Email
    r'\d{3}[-\.\s]?\d{2}[-\.\s]?\d{4}',  # SSN without dashes (e.g., 123.45.6789 or 123 45 6789)
    r'\b(?:\d{3}[ -]?\d{2}[ -]?\d{4})\b',  # SSN with optional spaces or dashes (e.g., 123-45 6789)
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])?[0-9]{11}|(?:2131|1800|35[0-9]{3})[0-9]{11})\b',  # Credit card numbers
    r'\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b',  # Date of birth (e.g., 01/01/2000, 1-1-00, 01-01-2000)
    r'(?:\+?1[-\.\s]?)?\(?(\d{3})\)?[-\.\s]?(\d{3})[-\.\s]?(\d{4})',  # US phone number
    r'[A-Z][a-z]+ [A-Z][a-z]+',  # Full name with two parts (e.g., John Doe)
    r'[A-Z][a-z]+ [A-Z]\.? [A-Z][a-z]+',  # Full name with middle initial (e.g., John A. Doe)
    r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}',  # Email (more general)
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IPv4 address
    # Add more PII patterns here
]

# Create an empty list to store results/matches
results = []
counter = 0

# Functions for scanning different sources
def scan_text(text):
    for pattern in pii_patterns:
        matches = re.findall(pattern, text)
        if matches:
            return matches
        else:
            return None

def scan_files(path):
    for root, _, files in os.walk(path):
        for file in enumerate(files):
            file_path = os.path.join(root, file)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                matches = scan_text(content)
                if matches:
                    print(f"PII found in {file_path}: {matches}")
                    results.append({
                        "Serial Number": counter+1,
                        "PII Data": ", ".join(matches),
                        "File Path": os.path.abspath(file)
                        })
                    counter += 1


def scan_smb(host, username, password, domain):
    connection = SMBConnection(username, password, 'local_machine', host, domain=domain, use_ntlm_v2=True)
    connection.connect(host)
    shares = connection.listShares()

    for share in shares:
        # Only scan shares that are not system shares
        if share.isSpecial:
            continue

        # Connect to the share
        shared_device = SMBConnection(host, username, password, host, domain=domain, use_ntlm_v2=True)
        shared_device.connect(host, share.name)

        # scan files in the share recursively
        for root, _, files in shared_device.listPath(share.name, "/"):
            for file in files:
                file_path = os.path.join(root, file.filename)
                try:
                    with shared_device.openFile(share.name, file_path, 'rb') as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        matches = scan_text(content)
                        if matches:
                            print(f"PII found in {file_path}: {matches}")
                            results.append({
                                "Serial Number": counter+1,
                                "PII Data": ", ".join(matches),
                                "File Path": os.path.abspath(file)
                            })
                            counter += 1
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")

def scan_ftp(host, username, password):
    ftp = ftplib.FTP(host)
    ftp.login(username, password)
    ftp.cwd('/')
    files = ftp.nlst()
    for file in files:
        with ftp.open(file, 'r') as f:
            content = f.read()
            matches = scan_text(content)
            if matches:
                print(f"PII found in {file}: {matches}")
                results.append({
                    "Serial Number": counter+1,
                    "PII Data": ", ".join(matches),
                    "File Path": os.path.abspath(file)
                })
                counter += 1
    ftp.quit()

def scan_db(host, username, password, db_name):
    connection = pymysql.connect(host=host, user=username, password=password, db=db_name, cursorclass=pymysql.cursors.DictCursor)
    cursor = connection.cursor()

    # Get list of tables in the database
    cursor.execute("SHOW TABLES")
    tables = [table['Tables_in_' + db_name] for table in cursor.fetchall()]

    # Loop through each table
    for table in tables:
        # Get list of columns in the table
        cursor.execute(f"DESCRIBE {table}")
        columns = [column['Field'] for column in cursor.fetchall()]

        # Loop through each column and scan for PII
        for column in columns:
            # Construct SELECT statement for the column
            select_query = f"SELECT {column} FROM {table}"
            cursor.execute(select_query)

            # Loop through each row in the column and scan for PII
            for row in cursor.fetchall():
                if row[column] is not None:
                    matches = scan_text(row[column])
                    if matches:
                        print(f"PII found in {db_name}.{table}.{column}: {matches}")
                        results.append({
                            "Serial Number": counter+1,
                            "PII Data": ", ".join(matches),
                            "File Path": os.path.abspath(file)
                        })
                        counter += 1

    connection.close()

# Main function
def main():
    print("Please choose the scanning type:")
    print("1. Credentialed")
    print("2. Uncredentialed")
    choice = int(input("Enter the number corresponding to your choice: "))

    if choice == 1:
        username = input("Enter the username: ")
        password = getpass.getpass("Enter the password: ")

        # Scan local file shares
        scan_files('path/to/file/share')

        # Scan SMB
        smb_host = input("Enter the SMB host: ")
        smb_domain = input("Enter the SMB domain: ")
        scan_smb(smb_host, username, password, smb_domain)

        # Scan FTP
        ftp_host = input("Enter the FTP host: ")
        scan_ftp(ftp_host, username, password)

        # Scan databases
        db_host = input("Enter the database host: ")
        db_name = input("Enter the database name: ")
        scan_db(db_host, username, password, db_name)

        # Save results to CSV file
        with open("results.csv", "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["Serial Number", "PII Data", "File Path"])
            writer.writeheader()
            for result in results:
                writer.writerow(result)       

        print(f"Found {len(results)} file(s) with PII data. Results saved to 'results.csv'.") 

    elif choice == 2:
        # Implement uncredentialed scanning logic
        pass

    else:
        print("Invalid choice. Please select a valid option.")

if __name__ == '__main__':
    main()
