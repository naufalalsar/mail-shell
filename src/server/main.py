import imaplib
import email
from email.header import decode_header
import os
import time
from datetime import datetime
from dotenv import load_dotenv
import json
import subprocess
import smtplib
from email.message import EmailMessage
import csv

# --- Load environment variables from .env file ---
load_dotenv()

# --- Load All Configuration from .env ---
USERNAME = os.getenv("EMAIL_USERNAME")
PASSWORD = os.getenv("EMAIL_PASSWORD")
SERVER = os.getenv("EMAIL_SERVER")
SERVER_NUMBER = os.getenv("SERVER_NUMBER")
SMTP_SERVER = os.getenv("SMTP_SERVER")

# --- Log File Configuration ---
LOGS_DIR = "logs"
CSV_LOG_FILE = os.path.join(LOGS_DIR, "executed_commands.csv")

def setup_logging():
    """Create the logs directory and necessary log files if they don't exist."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(CSV_LOG_FILE):
        with open(CSV_LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["sequence_number", "command", "time_sent", "status"])

def load_processed_sequences():
    """Reads the CSV file to get a set of already processed sequence numbers."""
    processed = set()
    try:
        with open(CSV_LOG_FILE, 'r', newline='') as f:
            reader = csv.reader(f)
            next(reader) # Skip header
            for row in reader:
                processed.add(int(row[0]))
    except (FileNotFoundError, IndexError, StopIteration):
        pass # File might be empty or not exist yet
    return processed

def log_command_activity(sequence_number, message):
    """Appends a timestamped message to a command-specific log file."""
    log_file = os.path.join(LOGS_DIR, f"command_{sequence_number}.txt")
    with open(log_file, 'a') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def log_to_csv(data, status):
    """Appends a record of an executed command to the .csv file."""
    with open(CSV_LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([data.get('sequence_number'), data.get('command'), data.get('time_sent'), status])

def send_reply_email(original_data, command_output):
    """Constructs and sends a JSON reply email."""
    seq_num = original_data.get("sequence_number")
    try:
        reply_data = {
            "sequence_number": seq_num,
            "command": original_data.get("command"),
            "command_reply": command_output,
            "server_number": int(SERVER_NUMBER),
            "time_replied": datetime.now().isoformat(),
            "time_sent": original_data.get("time_sent")
        }
        
        reply_json_string = json.dumps(reply_data, indent=2)

        msg = EmailMessage()
        msg['Subject'] = "MAIL SHELL REPLY"
        msg['From'] = USERNAME
        msg['To'] = USERNAME
        msg.set_content(reply_json_string)

        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            server.login(USERNAME, PASSWORD)
            server.send_message(msg)
        
        log_command_activity(seq_num, f"Successfully sent reply with content:\n{reply_json_string}")
    except Exception as e:
        log_command_activity(seq_num, f"Failed to send reply email. Error: {e}")

def execute_command(command_string, sequence_number):
    """
    Executes a given command string on the system and returns its output.
    WARNING: This function will execute ANY command received.
    """
    try:
        log_command_activity(sequence_number, f"Executing command: '{command_string}'")
        result = subprocess.run(command_string, shell=True, capture_output=True, text=True)
        
        output = result.stdout.strip()
        if result.stderr:
            output += f"\nERROR: {result.stderr.strip()}"
        
        log_command_activity(sequence_number, f"Command output: {output}")
        return output
    except Exception as e:
        error_message = f"An error occurred during command execution: {e}"
        log_command_activity(sequence_number, error_message)
        return error_message

def check_emails(processed_sequences):
    """Checks for new command emails and processes only one per cycle."""
    try:
        mail = imaplib.IMAP4_SSL(SERVER)
        mail.login(USERNAME, PASSWORD)
        mail.select("inbox")
        # --- MODIFICATION ---
        # Search for ALL emails matching criteria, not just UNSEEN ones.
        search_criteria = f'(FROM "{USERNAME}" SUBJECT "MAIL SHELL")'
        status, messages = mail.search(None, search_criteria)
        email_ids = messages[0].split()

        if email_ids:
            # We iterate through all matching emails to find the first one not yet processed.
            for email_id in email_ids:
                status, msg_data = mail.fetch(email_id, "(RFC822)")
                msg = email.message_from_bytes(msg_data[0][1])
                
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            break
                else:
                    body = msg.get_payload(decode=True).decode()
                
                if not body:
                    continue

                try:
                    data = json.loads(body)
                    seq_num = data.get("sequence_number")

                    if not seq_num:
                        continue
                    
                    # --- CORE LOGIC CHANGE ---
                    # The main check is now against our local log.
                    if seq_num in processed_sequences:
                        # This command has already been logged, so we skip it.
                        continue

                    log_command_activity(seq_num, "Processing new command email.")
                    
                    server_num = data.get("server_number")
                    if str(server_num) != SERVER_NUMBER:
                        log_command_activity(seq_num, f"Skipping: command is for server #{server_num} (this is server #{SERVER_NUMBER}).")
                        continue
                    
                    command = data.get("command")
                    if command:
                        output = execute_command(command, seq_num)
                        send_reply_email(data, output)
                        log_to_csv(data, "executed")
                        processed_sequences.add(seq_num)
                        
                        # --- MODIFICATION ---
                        # The mail.store() command has been removed.
                        
                        print(f"Processed command #{seq_num}. Will wait for the next cycle.")
                        # We found an unprocessed command and handled it, so we break to wait.
                        break
                    else:
                        log_command_activity(seq_num, "JSON is missing the 'command' key.")

                except (json.JSONDecodeError, AttributeError):
                    print("Could not parse JSON from an email body.")
            else: # This 'else' belongs to the 'for' loop
                print("No new commands found in the inbox.")
        else:
            print("No command emails found on the server.")
        
        mail.close()
        mail.logout()
    except Exception as e:
        print(f"An error occurred in check_emails: {e}")

# --- Main Loop ---
if __name__ == "__main__":
    if not all([USERNAME, PASSWORD, SERVER, SERVER_NUMBER, SMTP_SERVER]):
        print("Error: Ensure .env file has EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_SERVER, SERVER_NUMBER, and SMTP_SERVER.")
    else:
        setup_logging()
        processed_sequences = load_processed_sequences()
        print(f"Starting email checker for server #{SERVER_NUMBER}. Loaded {len(processed_sequences)} processed commands.")
        print("Press Ctrl+C to stop.")
        while True:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n--- [{current_time}] Checking for emails ---")
            check_emails(processed_sequences)
            wait_time = 15 * 60
            print(f"--- Check complete. Waiting for {wait_time / 60} minutes... ---")
            time.sleep(wait_time)