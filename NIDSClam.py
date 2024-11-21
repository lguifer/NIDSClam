  GNU nano 8.1                                                                                                                                                                                                                                                                                                                                                                                                                                                                   virus-scanner_v5.py                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
import os
import socket
import json
import subprocess
import argparse
import logging
import re
from datetime import datetime, timezone

# Define the log file path as a global variable
LOG_FILE_PATH = "/var/log/virus-scanner/virus-scanner.log"
hostname = socket.gethostname()

# Ensure the log directory exists
log_dir = os.path.dirname(LOG_FILE_PATH)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Create the log file if it doesn't exist
if not os.path.exists(LOG_FILE_PATH):
    open(LOG_FILE_PATH, 'w').close()

# Set up logging configuration
logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - NIDS - %(message)s",
        handlers=[
                logging.FileHandler(LOG_FILE_PATH),
                logging.StreamHandler()  # Also log to the console for visibility
        ]
)
logger = logging.getLogger(__name__)
logger = logging.LoggerAdapter(logger, {'hostname': socket.gethostname()})

# Argument parser setup
parser = argparse.ArgumentParser(description="Virus Scanner with Suricata and Zeek log processing")
parser.add_argument("--date-config-path", help="Path to store the last processed date")
parser.add_argument("--filestore-path", help="Path to file storage for scanning")
parser.add_argument("--suricata-log-file", help="Path to the Suricata log file")
parser.add_argument("--zeek-log-file", help="Path to the Zeek log file")
parser.add_argument("--recursive", action="store_true", help="Recursively search in filestore-path")
parser.add_argument("--file-or-dir", help="File or directory to scan directly if no log file is provided")
args = parser.parse_args()

# Set default path for date config file if not provided
if not args.date_config_path:
        args.date_config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "last_processed_date.txt")

# Function to read the last processed date
def read_last_processed_date():
        if os.path.exists(args.date_config_path):
                with open(args.date_config_path, 'r') as date_file:
                        return date_file.read().strip()
        else:
                with open(args.date_config_path, 'w') as date_file:
                        date_file.write("")
                return None

# Function to write the new processed date
def write_last_processed_date(date_str):
        with open(args.date_config_path, 'w') as date_file:
                date_file.write(date_str)

# Read the last processed date
last_processed_date_str = read_last_processed_date()
last_processed_date = datetime.fromisoformat(last_processed_date_str) if last_processed_date_str else None

# Process logs or a direct file/directory scan
def process_logs():
        if args.suricata_log_file:
                print("Processing Suricata log file...")
                process_suricata_log(args.suricata_log_file)
        elif args.zeek_log_file:
                print("Processing Zeek log file...")
                process_zeek_log(args.zeek_log_file)
        elif args.file_or_dir:
                print(f"Processing file or directory: {args.file_or_dir}")
                process_direct_file_or_dir(args.file_or_dir)
        else:
                print("No log file or file/directory specified for processing.")

# Direct file or directory processing
def process_direct_file_or_dir(file_or_dir):
        if os.path.isfile(file_or_dir):
                process_event(None, "N/A", "N/A", file_or_dir, datetime.now(timezone.utc))
        elif os.path.isdir(file_or_dir):
                for root, dirs, files in os.walk(file_or_dir):
                        for file in files:
                                file_path = os.path.join(root, file)
                                process_event(None, "N/A", "N/A", file_path, datetime.now(timezone.utc))
        else:
                print(f"Invalid path: {file_or_dir}")

# Process Suricata logs
def process_suricata_log(suricata_log_file):
        with open(suricata_log_file, 'r') as log_file:
                for line in log_file:
                        try:
                                eve = json.loads(line)
                        except json.JSONDecodeError:
                                print("An error occurred while reading events")
                                continue

                        if eve.get('event_type') == "fileinfo":
                                event_timestamp = datetime.fromisoformat(eve.get('timestamp').rstrip('Z'))

                                if last_processed_date and event_timestamp <= last_processed_date:
                                        continue
                                process_event(eve, eve.get('src_ip'), eve.get('dest_ip'), eve['fileinfo']['filename'], event_timestamp)

# Process Zeek logs
def process_zeek_log(zeek_log_file):
        # Run 'zeek-cut' command using subprocess
        command = f"cat {zeek_log_file} | zeek-cut id.orig_h id.resp_h extracted"
        
        # Execute the command in the shell and capture the output
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
                print(f"Error in executing zeek-cut: {stderr.decode()}")
                return
        
        # Process the output of the command
        for line in stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 3:
                        src_ip = parts[0]  # id.orig_h
                        dest_ip = parts[1]  # id.resp_h
                        filename = parts[2]  # extracted
                        print(f"src: {src_ip}, dst: {dest_ip}, path: {filename}") 
                        event_timestamp = datetime.now(timezone.utc)
                        process_event({}, src_ip, dest_ip, filename, event_timestamp)

def process_event(eve, src_ip, dest_ip, filename, event_timestamp):
        if eve is not None and args.suricata_log_file:
                name = eve['fileinfo']['sha256'] if 'fileinfo' in eve else 'unknown'
        elif args.zeek_log_file:  
                name = filename  
                # Run 'find' to search the file in filestore_path

        if args.file_or_dir is None:    
                find_command = ['find', args.filestore_path, '-name', name]
                try:
                        # Capture the result of 'find' and strip any newlines
                        captured_file = subprocess.run(
                                find_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                        ).stdout.strip()
                        
                        # If the file is not found, capture a warning message
                        if not captured_file:
                                return  # Exit the function if the file does not exist

                except Exception as e:
                        logger.error(f"Error executing 'find' for {name}: {e}")
                        return
        else:
                captured_file = filename  # Use directly the name if it's not a Suricata event

        # Run the file scan with ClamAV
        scan_result = subprocess.run(
                ['clamdscan', '--no-summary', '--stdout', '--stream', captured_file],
                stdout=subprocess.PIPE, text=True
        ).stdout.strip()

        # Generate the log message with the event details
        log_message = (f"Generated by virus-scanner at timestamp={event_timestamp} "
                                   f"src_ip={src_ip} dest_ip={dest_ip} "
                                   f"filename={filename} scan={scan_result}")

        # If a threat is detected (FOUND), log and display the message
        if re.search(r"FOUND\b", scan_result):
                logger.info(log_message)

        # Save the date of the last processed event if it's a Suricata event
        if eve is not None:
                write_last_processed_date(event_timestamp.isoformat())

# Run log processing based on arguments
process_logs()




