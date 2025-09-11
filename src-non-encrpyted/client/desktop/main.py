import smtplib
import json
import os
from datetime import datetime
from email.message import EmailMessage
from dotenv import load_dotenv
import imaplib
import email
import csv
import uuid

# --- Load environment variables from .env file ---
load_dotenv()

# --- Load Configuration from .env ---
USERNAME = os.getenv("EMAIL_USERNAME")
PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
IMAP_SERVER = os.getenv("EMAIL_SERVER")

# --- Log File Configuration ---
LOGS_DIR = "logs"
SENT_LOGS_DIR = os.path.join(LOGS_DIR, "sent")
REPLY_LOGS_DIR = os.path.join(LOGS_DIR, "replies")
SENT_CSV_LOG = os.path.join(SENT_LOGS_DIR, "sent_commands.csv")
REPLY_CSV_LOG = os.path.join(REPLY_LOGS_DIR, "received_replies.csv")

def setup_logging():
    """Create the logs directory and subdirectories with CSV files and headers if they don't exist."""
    os.makedirs(SENT_LOGS_DIR, exist_ok=True)
    os.makedirs(REPLY_LOGS_DIR, exist_ok=True)
    if not os.path.exists(SENT_CSV_LOG):
        with open(SENT_CSV_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["uuid", "command", "server_number", "time_sent"])
    if not os.path.exists(REPLY_CSV_LOG):
        with open(REPLY_CSV_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["uuid", "command", "time_replied", "status"])

def log_to_csv(filepath, data, headers):
    """Appends a row of data to the specified CSV file."""
    with open(filepath, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([data.get(h, 'N/A') for h in headers])

def log_to_txt(filepath, json_payload):
    """Saves the JSON payload to a text file."""
    with open(filepath, 'w') as f:
        f.write(json_payload)

def send_command_email():
    """Guides the user to send a new plaintext command email and logs the action."""
    print("\n--- Send New Command (Unencrypted) ---")
    command = input("Enter command to send: ")
    while True:
        server_str = input("Enter target server number: ")
        try:
            server_number = int(server_str)
            break
        except ValueError:
            print("Invalid input. Please enter a whole number.")

    command_uuid = str(uuid.uuid4())
    print(f"Generated new command UUID: {command_uuid}")

    command_data = {
        "command": command,
        "time_sent": datetime.now().isoformat(),
        "uuid": command_uuid,
        "server_number": server_number
    }
    json_payload_to_send = json.dumps(command_data, indent=2)

    msg = EmailMessage()
    msg['Subject'] = "MAIL SHELL"
    msg['From'] = USERNAME
    msg['To'] = USERNAME
    msg.set_content(json_payload_to_send)

    try:
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            server.login(USERNAME, PASSWORD)
            server.send_message(msg)
        print("\nCommand email sent successfully!")
        
        log_to_csv(SENT_CSV_LOG, command_data, ["uuid", "command", "server_number", "time_sent"])
        log_file_path = os.path.join(SENT_LOGS_DIR, f"sent_{command_uuid}.txt")
        log_to_txt(log_file_path, json_payload_to_send)
        print(f"Sent command logged to {SENT_CSV_LOG} and {log_file_path}")

    except Exception as e:
        print(f"\nFailed to send email. Error: {e}")

def load_processed_replies():
    """Reads the replies CSV to get a set of already logged UUIDs."""
    processed = set()
    try:
        with open(REPLY_CSV_LOG, 'r', newline='') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                processed.add(row[0])
    except (FileNotFoundError, IndexError, StopIteration):
        pass
    return processed

def sync_replies():
    """Connects to the server, fetches plaintext replies, and logs new ones."""
    print("\n--- Syncing Replies ---")
    processed_replies = load_processed_replies()
    print(f"Found {len(processed_replies)} replies already logged locally.")
    print("Connecting to email server to fetch new replies...")
    replies_synced = 0
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USERNAME, PASSWORD)
        mail.select("inbox")
        search_criteria = '(SUBJECT "MAIL SHELL REPLY")'
        status, messages = mail.search(None, search_criteria)
        email_ids = messages[0].split()

        if not email_ids:
            print("No replies found on the server.")
            mail.logout()
            return

        for email_id in reversed(email_ids):
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
            
            try:
                data = json.loads(body)
                command_uuid = data.get("uuid")
                if command_uuid and command_uuid not in processed_replies:
                    reply_json_string = json.dumps(data, indent=2)
                    log_to_csv(REPLY_CSV_LOG, data, ["uuid", "command", "time_replied", "status"])
                    log_file_path = os.path.join(REPLY_LOGS_DIR, f"reply_{command_uuid}.txt")
                    log_to_txt(log_file_path, reply_json_string)
                    processed_replies.add(command_uuid)
                    replies_synced += 1
            except (json.JSONDecodeError, AttributeError):
                continue
        
        print(f"\nSync complete. Fetched and logged {replies_synced} new replies.")
        mail.close()
        mail.logout()
    except Exception as e:
        print(f"An error occurred while syncing replies: {e}")

def view_logs_paginated():
    """Displays a paginated list of sent commands and allows viewing details."""
    print("\n--- View Command Logs ---")
    try:
        with open(SENT_CSV_LOG, 'r', newline='') as f:
            reader = csv.DictReader(f)
            all_logs = list(reader)[::-1]
    except FileNotFoundError:
        print("No logs found. Send a command first.")
        return

    if not all_logs:
        print("Log file is empty.")
        return

    page_size = 10
    current_page = 0
    total_logs = len(all_logs)
    total_pages = (total_logs + page_size - 1) // page_size

    while True:
        print(f"\n--- Sent Commands (Page {current_page + 1}/{total_pages}) ---")
        start_index = current_page * page_size
        end_index = start_index + page_size
        logs_for_page = all_logs[start_index:end_index]

        for i, log in enumerate(logs_for_page, start=1):
            time_str = log.get('time_sent', '')
            display_time = time_str[:19] if time_str else "N/A"
            print(f"  {i}. [{display_time}] CMD: \"{log.get('command', '')}\" UUID: {log.get('uuid', '')[:8]}...")
        
        print("\nOptions: (N)ext, (P)revious, (Enter a number to view details), (Q)uit")
        action = input("Enter action: ").lower()

        if action == 'n':
            if current_page < total_pages - 1:
                current_page += 1
        elif action == 'p':
            if current_page > 0:
                current_page -= 1
        elif action == 'q':
            break
        else:
            try:
                selection = int(action)
                if 1 <= selection <= len(logs_for_page):
                    selected_uuid = logs_for_page[selection - 1].get('uuid')
                    if selected_uuid:
                        display_log_details(selected_uuid)
                else:
                    print("Invalid number. Please select a number from the list.")
            except ValueError:
                print("Invalid action.")

def display_log_details(uuid_to_find):
    """Displays the full .txt logs for a given UUID."""
    sent_log_path = os.path.join(SENT_LOGS_DIR, f"sent_{uuid_to_find}.txt")
    reply_log_path = os.path.join(REPLY_LOGS_DIR, f"reply_{uuid_to_find}.txt")
    
    log_found = False
    if os.path.exists(sent_log_path):
        with open(sent_log_path, 'r') as f:
            print("\n--- Sent Command Details ---")
            print(f.read())
            print("--------------------------")
            log_found = True
    
    if os.path.exists(reply_log_path):
        with open(reply_log_path, 'r') as f:
            print("\n--- Received Reply Details ---")
            print(f.read())
            print("----------------------------")
            log_found = True
            
    if not log_found:
        print(f"No detailed .txt logs found for UUID {uuid_to_find}.")

def interactive_mode():
    """Runs the main interactive command prompt."""
    setup_logging()
    print("--- Mail Commander (Unencrypted Mode) ---")
    
    while True:
        print("\nAvailable actions: [send], [sync] replies, [read] logs, [quit]")
        action = input("Enter action: ").lower()

        if action == 'send':
            send_command_email()
        elif action == 'sync':
            sync_replies()
        elif action == 'read':
            view_logs_paginated()
        elif action == 'quit':
            break
        else:
            print("Invalid action. Please choose 'send', 'sync', 'read', or 'quit'.")

if __name__ == "__main__":
    if not all([USERNAME, PASSWORD, SMTP_SERVER, IMAP_SERVER]):
        print("Error: Ensure .env file has all required client variables.")
    else:
        interactive_mode()
