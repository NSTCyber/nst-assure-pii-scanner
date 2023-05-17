import os
import re
import socket
import ftplib
import getpass
from smb.SMBConnection import SMBConnection
import pymysql
import pyodbc
import psycopg2
import cx_Oracle
import pymssql
from sqlalchemy import create_engine, inspect
import csv
import getpass

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
    r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', # Credit/Debit Card Number
    r'\b[A-Za-z\s]+\b', # Card Holder Name
    r'\b(?:0[1-9]|1[0-2])/\d{2}\b', # Expiration Date
    r'\b\d{3}\b', # Service Code
    r'\b\d{3,4}\b', # CVV/CVC
    r'\b\d{4,6}\b', # PIN
    r'\b\d{12,19}\b', # Account Number
    # Add more PII patterns here
]

# Create an empty list to store results/matches
results = []
counter = 0

# Functions for scanning different sources
def scan_text(text):
    try:
        for pattern in pii_patterns:
            matches = re.findall(pattern, text)
            if matches:
                return matches
        return None
    except Exception as e:
        print(f"An error occurred while scanning the text: {e}")

def scan_files(path):
    try:
        results = []
        counter = 0
        for root, _, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        matches = scan_text(content)
                        if matches:
                            print(f"PII found in {file_path}: {matches}")
                            results.append({
                                "Serial Number": counter+1,
                                "PII Data": ", ".join(matches),
                                "Location": os.path.abspath(file_path)
                            })
                            counter += 1
                except Exception as e:
                    print(f"Error while processing file {file_path}: {e}")
        return results
    except Exception as e:
        print(f"Error while scanning files: {e}")

def scan_smb(host, username, password, domain):
    try:
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
                                    "Location": os.path.abspath(file)
                                })
                                counter += 1
                    except Exception as e:
                        print(f"Error scanning {file_path}: {e}")
    except Exception as e:
        print(f"Error connecting to {host}: {e}")

def scan_smb_uncred(host, username='guest', password='', domain=''):
    try:
        connection = SMBConnection(username, password, 'local_machine', host, domain=domain, use_ntlm_v2=True)
        connection.connect(host)
        shares = connection.listShares()
    except Exception as e:
        print(f"Error connecting to {host}: {e}")
        return

    for share in shares:
        # Only scan shares that are not system shares
        if share.isSpecial:
            continue

        try:
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
                                    "Location": os.path.abspath(file)
                                })
                                counter += 1
                    except Exception as e:
                        print(f"Error scanning {file_path}: {e}")
        except Exception as e:
            print(f"Error connecting to share {share.name}: {e}")

def scan_ftp(host, username, password):
    try:
        ftp = ftplib.FTP(host)
        ftp.login(username, password)
        ftp.cwd('/')
        files = ftp.nlst()
        for file in files:
            try:
                with ftp.open(file, 'r') as f:
                    content = f.read()
                    matches = scan_text(content)
                    if matches:
                        print(f"PII found in {file}: {matches}")
                        results.append({
                            "Serial Number": counter+1,
                            "PII Data": ", ".join(matches),
                            "Location": os.path.abspath(file)
                        })
                        counter += 1
            except Exception as e:
                print(f"Error scanning {file}: {e}")
        ftp.quit()
    except Exception as e:
        print(f"Error connecting to FTP server: {e}")


def scan_ftp_uncred(host):
    try:
        ftp = ftplib.FTP(host)
        ftp.login()
        ftp.cwd('/')
        files = ftp.nlst()
        counter = 0
        results = []
        for file in files:
            try:
                with ftp.open(file, 'r') as f:
                    content = f.read()
                    matches = scan_text(content)
                    if matches:
                        print(f"PII found in {file}: {matches}")
                        results.append({
                            "Serial Number": counter+1,
                            "PII Data": ", ".join(matches),
                            "Location": os.path.abspath(file)
                        })
                        counter += 1
            except Exception as e:
                print(f"Error scanning {file}: {e}")
        ftp.quit()
        return results
    except Exception as e:
        print(f"Error connecting to {host}: {e}")
        return []

#Scan Database Credentialed

def scan_db(db_type, host, port, username, password):
    results = []
    counter = 0
    
    try:
        if db_type == 'mysql':
            connection = pymysql.connect(host=host, user=username, password=password, cursorclass=pymysql.cursors.DictCursor)
            cursor = connection.cursor()
            cursor.execute("SHOW DATABASES")
            db_names = [db['Database'] for db in cursor.fetchall()]
        elif db_type == 'mssql':
            connection = pymssql.connect(server=host, user=username, password=password)
            cursor = connection.cursor(as_dict=True)
            cursor.execute("SELECT name FROM sys.databases")
            db_names = [db[0] for db in cursor.fetchall()]
        elif db_type == 'postgresql':
            connection = psycopg2.connect(host=host, user=username, password=password)
            cursor = connection.cursor()
            cursor.execute("SELECT datname FROM pg_database")
            db_names = [db[0] for db in cursor.fetchall()]
        elif db_type == 'oracledb':
            dsn = cx_Oracle.makedsn(host, port, service_name=service_name)
            connection = cx_Oracle.connect(user=username, password=password, dsn=dsn)
            cursor = connection.cursor()
            cursor.execute("SELECT name FROM v$database")
            db_names = [db[0] for db in cursor.fetchall()]

        # Loop through each database
        for db_name in db_names:
            # Select the database
            if db_type == 'mysql' or db_type == 'postgresql' or db_type == 'oracledb':
                cursor.execute(f"USE {db_name}")
            elif db_type == 'mssql':
                cursor.execute(f"USE [{db_name}]")

            # Get list of tables in the database
            if db_type == 'mssql':
                cursor.execute("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_TYPE='BASE TABLE'")
            else:
                cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]

            # Loop through each table
            for table in tables:
                # Get list of columns in the table
                if db_type == 'mssql':
                    cursor.execute(f"SELECT COLUMN_NAME FROM information_schema.columns WHERE TABLE_NAME = '{table}'")
                else:
                    cursor.execute(f"DESCRIBE {table}")
                columns = [column['Field'] if db_type == 'mysql' or db_type == 'postgresql' or db_type == 'oracledb' else column['COLUMN_NAME'] for column in cursor.fetchall()]

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
                                print(f"PII found in {db_name} in {table}: {matches}")
                                results.append({
                                    "Serial Number": counter+1,
                                    "PII Data": ", ".join(matches),
                                    "Location": f"{table}.{column} in {db_name}"
                                })
                                counter += 1

        connection.close()

    except Exception as e:
        print(f"Error scanning databases: {e}")
        results = []

    return results

# Scan Database UnCredentialed

def scan_db_uncred(db_type, host):
    results = []
    counter = 0
    try:
        # Set the driver based on the database type
        if db_type == 'mysql':
            driver = 'MySQL ODBC 8.0 ANSI Driver'
            dsn = f"Driver={{{driver}}};Server={host};Trusted_Connection=yes;"
        elif db_type == 'mssql':
            driver = 'SQL Server'
            dsn = f"Driver={{{driver}}};Server={host};Trusted_Connection=yes;"
        elif db_type == 'postgresql':
            driver = 'PostgreSQL ANSI'
            dsn = f"Driver={{{driver}}};Server={host};Trusted_Connection=yes;"
        elif db_type == 'oracledb':
            driver = 'Oracle in instantclient_19_11'
            dsn = f"Driver={{{driver}}};DBQ={host};Uid=/;Pwd=/;"
        else:
            raise ValueError(f"Invalid db_type: {db_type}")

        connection = pyodbc.connect(dsn)
        cursor = connection.cursor()

        # Get list of databases in the server
        if db_type == 'mysql':
            cursor.execute("SHOW DATABASES")
            databases = [database[0] for database in cursor.fetchall()]
        elif db_type == 'mssql':
            cursor.execute("SELECT name FROM master.dbo.sysdatabases")
            databases = [database[0] for database in cursor.fetchall()]
        elif db_type == 'postgresql':
            cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
            databases = [database[0] for database in cursor.fetchall()]
        elif db_type == 'oracledb':
            cursor.execute("SELECT name FROM v$database")
            databases = [database[0] for database in cursor.fetchall()]

        # Loop through each database
        results = []
        counter = 0
        for database in databases:
            # Get list of tables in the database
            cursor.execute(f"SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema = '{database}'")
            tables = [table[0] for table in cursor.fetchall()]

            # Loop through each table
            for table in tables:
                # Get list of columns in the table
                cursor.execute(f"SELECT column_name FROM information_schema.columns WHERE table_name='{table}' AND table_schema = '{database}'")
                columns = [column[0] for column in cursor.fetchall()]

                # Loop through each column and scan for PII
                for column in columns:
                    # Construct SELECT statement for the column
                    select_query = f"SELECT {column} FROM {database}.{table}"
                    cursor.execute(select_query)

                    # Loop through each row in the column and scan for PII
                    for row in cursor.fetchall():
                        if row[column] is not None:
                            matches = scan_text(row[column])
                            if matches:
                                print(f"PII found in {database} in {table}.{column}: {matches}")
                                results.append({
                                    "Serial Number": counter+1,
                                    "PII Data": ", ".join(matches),
                                    "Location": f"{table}.{column} in {database}"
                                })
                                counter += 1

        connection.close()

    except pyodbc.Error as e:
        print(f"Error connecting to database: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")

    return results


# Main function

def main():
    print("Please choose the scanning type:")
    print("1. Credentialed")
    print("2. Uncredentialed")
    choice = input("Enter the number corresponding to your choice: ")

    if choice == "1":
        try:
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            
            # Scan local file shares
            filepath1 = input("Enter the path to fileshare: ")
            scan_files(filepath1)

            # Scan SMB
            smb_host = input("Enter the SMB host: ")
            smb_domain = input("Enter the SMB domain: ")
            smb_user = input("Enter the SMB username: ")
            smb_password = getpass.getpass("Enter the SMB password: ")
            scan_smb(smb_host, smb_user, smb_password, smb_domain)

            # Scan FTP
            ftp_host = input("Enter the FTP host: ")
            ftp_user = input("Enter the FTP username: ")
            ftp_password = getpass.getpass("Enter the FTP password: ")
            scan_ftp(ftp_host, ftp_user, ftp_password)

            # Scan databases
            db_type = input("Enter the database type(mysql,mssql,postgresql,oracledb): ")
            db_host = input("Enter the database host: ")
            db_port = input("Enter the database port: ")
            db_user = input("Enter the database username: ")
            db_password = getpass.getpass("Enter the database password: ")
            scan_db(db_type, db_host, db_port, db_user, db_password)

            # Save results to CSV file
            with open('pii_results.csv', 'w', newline='') as csvfile:
                fieldnames = ['Serial Number', 'PII Data', 'Location']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for result in results:
                    writer.writerow(result)

            print(f"Found {len(results)} file(s) with PII data. Results saved to 'pii_results.csv'.") 
        except Exception as e:
            print(f"An error occurred: {e}")

    elif choice == "2":
        try:
            # Scan local file shares Uncredentialed
            filepath1 = input("Enter the path to fileshare: ")
            scan_files(filepath1)

            # Scan SMB Uncredentialed
            smb_host = input("Enter the SMB host: ")
            scan_smb_uncred(smb_host, "", "", "")

            # Scan FTP Uncredentialed
            ftp_host = input("Enter the FTP host: ")
            scan_ftp_uncred(ftp_host)

            # Scan Database Uncredentialed
            db_type = input("Enter the database type(mysql,mssql,postgresql,oracledb): ")
            db_host = input("Enter the database host: ")
            # db_port = input("Enter the database port: ")
            # db_name = input("Enter the database name: ")
            scan_db_uncred(db_type, db_host)

            # Save results to CSV file
            with open('pii_results.csv', 'w', newline='') as csvfile:
                fieldnames = ['Serial Number', 'PII Data', 'Location']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for result in results:
                    writer.writerow(result)

            print(f"Found {len(results)} file(s) with PII data. Results saved to 'pii_results.csv'.") 
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
