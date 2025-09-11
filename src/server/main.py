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
import uuid

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
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(CSV_LOG_FILE):
        with open(CSV_LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["uuid", "command", "time_sent", "status"])

def load_processed_uuids():
    processed = set()
    try:
        with open(CSV_LOG_FILE, 'r', newline='') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                processed.add(row[0])
    except (FileNotFoundError, IndexError, StopIteration):
        pass
    return processed

def log_command_activity(command_uuid, message):
    log_file = os.path.join(LOGS_DIR, f"command_{command_uuid}.txt")
    with open(log_file, 'a') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def log_to_csv(data, status):
    with open(CSV_LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([data.get('uuid'), data.get('command', 'N/A'), data.get('time_sent', 'N/A'), status])

def send_reply_email(original_data, command_output):
    command_uuid = original_data.get("uuid")
    try:
        reply_data = {
            "uuid": command_uuid,
            "command": original_data.get("command"),
            "time_sent": original_data.get("time_sent"),
            "command_reply": command_output,
            "server_number": int(SERVER_NUMBER),
            "time_replied": datetime.now().isoformat()
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
        
        log_command_activity(command_uuid, f"Successfully sent reply with content:\n{reply_json_string}")
    except Exception as e:
        log_command_activity(command_uuid, f"Failed to send reply email. Error: {e}")

def execute_command(command_string, command_uuid):
    try:
        log_command_activity(command_uuid, f"Executing command: '{command_string}'")
        result = subprocess.run(command_string, shell=True, capture_output=True, text=True)
        
        output_lines = result.stdout.strip().splitlines()
        if result.stderr:
            output_lines.append("--- STDERR ---")
            output_lines.extend(result.stderr.strip().splitlines())
        
        log_command_activity(command_uuid, f"Command output captured with {len(output_lines)} lines.")
        return output_lines
    except Exception as e:
        error_message = f"An error occurred during command execution: {e}"
        log_command_activity(command_uuid, error_message)
        return [error_message]

def check_emails(processed_uuids):
    try:
        mail = imaplib.IMAP4_SSL(SERVER)
        mail.login(USERNAME, PASSWORD)
        mail.select("inbox")
        search_criteria = f'(FROM "{USERNAME}" SUBJECT "MAIL SHELL")'
        status, messages = mail.search(None, search_criteria)
        email_ids = messages[0].split()

        if email_ids:
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
                
                if not body: continue

                try:
                    data = json.loads(body)
                    command_uuid = data.get("uuid")

                    if not command_uuid: continue
                    if command_uuid in processed_uuids: continue
                    
                    log_command_activity(command_uuid, "Processing new command email.")
                    
                    server_num = data.get("server_number")
                    if str(server_num) != SERVER_NUMBER:
                        log_command_activity(command_uuid, f"Skipping: for server #{server_num}.")
                        continue
                    
                    command = data.get("command")
                    if command:
                        output = execute_command(command, command_uuid)
                        send_reply_email(data, output)
                        log_to_csv(data, "executed")
                        processed_uuids.add(command_uuid)
                        print(f"Processed command UUID {command_uuid[:8]}...")
                        break

                except (json.JSONDecodeError, AttributeError):
                    print("Could not parse JSON from an email body.")
            else:
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
        print("Error: Ensure .env file has all required server variables.")
    else:
        print("Starting unencrypted email checker...")
        setup_logging()
        processed_uuids = load_processed_uuids()
        print(f"Starting email checker for server #{SERVER_NUMBER}. Loaded {len(processed_uuids)} commands.")
        print("Press Ctrl+C to stop.")
        while True:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n--- [{current_time}] Checking for emails ---")
            check_emails(processed_uuids)
            wait_time = 15 * 60
            print(f"--- Check complete. Waiting for {wait_time / 60} minutes... ---")
            time.sleep(wait_time)
