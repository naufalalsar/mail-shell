import smtplib
import json
import os
from datetime import datetime
from email.message import EmailMessage
from dotenv import load_dotenv
import imaplib
import email
from email.header import decode_header
import csv

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
            writer.writerow(["sequence_number", "command", "server_number", "time_sent"])
    if not os.path.exists(REPLY_CSV_LOG):
        with open(REPLY_CSV_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["sequence_number", "original_command", "time_replied"])

def log_to_csv(filepath, data, headers):
    """Appends a row of data to the specified CSV file."""
    with open(filepath, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([data.get(h) for h in headers])

def log_to_txt(filepath, json_payload):
    """Saves the JSON payload to a text file."""
    with open(filepath, 'w') as f:
        f.write(json_payload)

def get_next_sequence_number():
    """Connects to the email server, finds the most recent 'MAIL SHELL' email,
    reads its sequence number, and returns the next number in the sequence."""
    print("\nConnecting to email server to determine next sequence number...")
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USERNAME, PASSWORD)
        mail.select('"[Gmail]/Sent Mail"')
        status, messages = mail.search(None, '(SUBJECT "MAIL SHELL")')
        email_ids = messages[0].split()

        if not email_ids:
            mail.logout()
            print("No previous 'MAIL SHELL' commands found. Starting sequence at 1.")
            return 1

        # Get only the last (most recent) email ID
        last_email_id = email_ids[-1]
        
        status, msg_data = mail.fetch(last_email_id, "(RFC822)")
        msg = email.message_from_bytes(msg_data[0][1])
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode()
                    break
        else:
            body = msg.get_payload(decode=True).decode()
        
        last_sequence = 0
        try:
            data = json.loads(body)
            last_sequence = data.get("sequence_number", 0)
        except (json.JSONDecodeError, AttributeError):
            # If the last email is malformed, we can't get a number.
            # A more robust solution might search backwards, but for now we default.
            print("Warning: Could not parse the last command email. Defaulting to 1.")
            mail.logout()
            return 1 # Fallback
            
        mail.logout()
        print(f"Highest sequence number found: {last_sequence}. Next will be {last_sequence + 1}.")
        return last_sequence + 1
    except Exception as e:
        print(f"Could not retrieve sequence number: {e}. Defaulting to 1.")
        return 1

def send_command_email():
    """Guides the user to send a new command email and logs the action."""
    print("\n--- Send New Command ---")
    command = input("Enter command to send: ")
    while True:
        server_str = input("Enter target server number: ")
        try:
            server_number = int(server_str)
            break
        except ValueError:
            print("Invalid input. Please enter a whole number.")

    sequence_number = get_next_sequence_number()
    if sequence_number is None:
        print("Could not determine next sequence number. Aborting.")
        return

    command_data = {
        "command": command, "time_sent": datetime.now().isoformat(),
        "sequence_number": sequence_number, "server_number": server_number
    }
    json_payload = json.dumps(command_data, indent=2)

    msg = EmailMessage()
    msg['Subject'] = "MAIL SHELL"
    msg['From'] = USERNAME
    msg['To'] = USERNAME
    msg.set_content(json_payload)

    try:
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            server.login(USERNAME, PASSWORD)
            server.send_message(msg)
        print("\nCommand email sent successfully!")
        
        log_to_csv(SENT_CSV_LOG, command_data, ["sequence_number", "command", "server_number", "time_sent"])
        log_file_path = os.path.join(SENT_LOGS_DIR, f"sent_{sequence_number}.txt")
        log_to_txt(log_file_path, json_payload)
        print(f"Sent command logged to {SENT_CSV_LOG} and {log_file_path}")

    except Exception as e:
        print(f"\nFailed to send email. Error: {e}")

def load_processed_replies():
    """Reads the replies CSV to get a set of already logged sequence numbers."""
    processed = set()
    try:
        with open(REPLY_CSV_LOG, 'r', newline='') as f:
            reader = csv.reader(f)
            next(reader) # Skip header
            for row in reader:
                processed.add(int(row[0]))
    except (FileNotFoundError, IndexError, StopIteration):
        pass # File might be empty or not exist yet
    return processed

def sync_replies():
    """Connects to the server, fetches all replies, and logs ones not already in the local log."""
    print("\n--- Syncing Replies ---")
    processed_replies = load_processed_replies()
    print(f"Found {len(processed_replies)} replies already logged locally.")
    print("Connecting to email server to fetch new replies...")
    replies_synced = 0
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USERNAME, PASSWORD)
        mail.select("inbox")
        # Search for ALL replies, not just unseen ones
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
                seq_num = data.get("sequence_number")
                if seq_num and seq_num not in processed_replies:
                    # If the sequence number is new to us, log it.
                    reply_json_string = json.dumps(data, indent=2)
                    log_to_csv(REPLY_CSV_LOG, data, ["sequence_number", "original_command", "time_replied"])
                    log_file_path = os.path.join(REPLY_LOGS_DIR, f"reply_{seq_num}.txt")
                    log_to_txt(log_file_path, reply_json_string)
                    processed_replies.add(seq_num) # Add to our set for this session
                    replies_synced += 1
            except (json.JSONDecodeError, AttributeError):
                continue
        
        print(f"\nSync complete. Fetched and logged {replies_synced} new replies.")
        mail.close()
        mail.logout()
    except Exception as e:
        print(f"An error occurred while syncing replies: {e}")

def view_log():
    """Asks for a sequence number and displays the local logs for it."""
    print("\n--- View Command Log ---")
    try:
        seq_to_find_str = input("Enter the sequence number you want to view: ")
        seq_to_find = int(seq_to_find_str)
    except ValueError:
        print("Invalid input. Please enter a number.")
        return

    sent_log_path = os.path.join(SENT_LOGS_DIR, f"sent_{seq_to_find}.txt")
    reply_log_path = os.path.join(REPLY_LOGS_DIR, f"reply_{seq_to_find}.txt")
    
    log_found = False
    if os.path.exists(sent_log_path):
        with open(sent_log_path, 'r') as f:
            print("\n--- Sent Command ---")
            print(f.read())
            print("--------------------")
            log_found = True
    
    if os.path.exists(reply_log_path):
        with open(reply_log_path, 'r') as f:
            print("\n--- Received Reply ---")
            print(f.read())
            print("--------------------")
            log_found = True
            
    if not log_found:
        print(f"No local logs found for sequence number {seq_to_find}.")

def interactive_mode():
    """Runs the main interactive command prompt."""
    setup_logging()
    print("--- Mail Commander (Interactive Mode) ---")
    
    while True:
        print("\nAvailable actions: [send], [sync] replies, [read] logs, [quit]")
        action = input("Enter action: ").lower()

        if action == 'send':
            send_command_email()
        elif action == 'sync':
            sync_replies()
        elif action == 'read':
            view_log()
        elif action == 'quit':
            break
        else:
            print("Invalid action. Please choose 'send', 'sync', 'read', or 'quit'.")

if __name__ == "__main__":
    if not all([USERNAME, PASSWORD, SMTP_SERVER, IMAP_SERVER]):
        print("Error: Ensure .env file has EMAIL_USERNAME, EMAIL_PASSWORD, SMTP_SERVER, and EMAIL_SERVER.")
    else:
        interactive_mode()
