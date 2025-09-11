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
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# --- Load environment variables from .env file ---
load_dotenv()

# --- Load Configuration from .env ---
USERNAME = os.getenv("EMAIL_USERNAME")
PASSWORD = os.getenv("EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
IMAP_SERVER = os.getenv("EMAIL_SERVER")
CLIENT_NUMBER = os.getenv("CLIENT_NUMBER") # This client's unique ID (e.g., "1")

# --- Encryption Configuration (Hardcoded Paths) ---
SERVER_KEYS_DIR = "server_keys"
CLIENT_PRIVATE_KEY_PATH = f"{CLIENT_NUMBER}_private.pem"

# --- Log File Configuration ---
LOGS_DIR = "logs"
SENT_LOGS_DIR = os.path.join(LOGS_DIR, "sent")
REPLY_LOGS_DIR = os.path.join(LOGS_DIR, "replies")
SENT_CSV_LOG = os.path.join(SENT_LOGS_DIR, "sent_commands.csv")
REPLY_CSV_LOG = os.path.join(REPLY_LOGS_DIR, "received_replies.csv")

def load_server_public_keys():
    """Loads server public keys, mapping filenames like "1.pem" to integer ID 1."""
    keys = {}
    print(f"Loading server public keys from '{SERVER_KEYS_DIR}'...")
    try:
        if not os.path.isdir(SERVER_KEYS_DIR):
            print(f"Warning: Directory '{SERVER_KEYS_DIR}' not found. Cannot send commands.")
            return {}
        for filename in os.listdir(SERVER_KEYS_DIR):
            if filename.endswith(".pem"):
                server_id_str = os.path.splitext(filename)[0]
                filepath = os.path.join(SERVER_KEYS_DIR, filename)
                try:
                    server_id = int(server_id_str)
                    public_key = RSA.import_key(open(filepath).read())
                    keys[server_id] = PKCS1_OAEP.new(public_key)
                    print(f"  - Loaded key for server ID: {server_id}")
                except (ValueError, Exception) as e:
                    print(f"  - Failed to load key from {filename}. Error: {e}")
        return keys
    except Exception as e:
        print(f"An error occurred loading server keys: {e}")
        return {}

def setup_logging():
    os.makedirs(SENT_LOGS_DIR, exist_ok=True)
    os.makedirs(REPLY_LOGS_DIR, exist_ok=True)
    if not os.path.exists(SENT_CSV_LOG):
        with open(SENT_CSV_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["uuid", "command", "server_number", "time_sent", "client_number"])
    if not os.path.exists(REPLY_CSV_LOG):
        with open(REPLY_CSV_LOG, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["uuid", "command", "time_replied", "status"])

def log_to_csv(filepath, data, headers):
    with open(filepath, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([data.get(h, 'N/A') for h in headers])

def log_to_txt(filepath, json_payload):
    with open(filepath, 'w') as f:
        f.write(json_payload)

def send_command_email(server_keys):
    print("\n--- Send New Command ---")
    command = input("Enter command to send: ")
    while True:
        try:
            server_id_str = input(f"Enter target server ID {list(server_keys.keys())}: ")
            server_id = int(server_id_str)
            if server_id in server_keys:
                break
            else:
                print("Invalid server ID. Please choose from the available keys.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    
    rsa_cipher = server_keys[server_id]
    command_uuid = str(uuid.uuid4())
    print(f"Generated new command UUID: {command_uuid}")

    inner_command_data = {
        "command": command,
        "time_sent": datetime.now().isoformat(),
        "client_number": int(CLIENT_NUMBER)
    }

    print("Encrypting command payload using hybrid encryption...")
    inner_payload_bytes = json.dumps(inner_command_data).encode('utf-8')
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(inner_payload_bytes)
    encrypted_session_key = rsa_cipher.encrypt(session_key)

    final_payload_data = {
        "uuid": command_uuid,
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
        "nonce": base64.b64encode(cipher_aes.nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "server_number": server_id,
        "client_number": int(CLIENT_NUMBER)
    }
    
    json_payload_to_send = json.dumps(final_payload_data, indent=2)

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
        
        log_data = inner_command_data
        log_data['uuid'] = command_uuid
        log_data['server_number'] = server_id
        log_to_csv(SENT_CSV_LOG, log_data, ["uuid", "command", "server_number", "time_sent", "client_number"])
        
        log_file_path = os.path.join(SENT_LOGS_DIR, f"sent_{command_uuid}.txt")
        log_to_txt(log_file_path, json_payload_to_send)
        print(f"Sent command logged to {SENT_CSV_LOG} and {log_file_path}")

    except Exception as e:
        print(f"\nFailed to send email. Error: {e}")

def load_processed_replies():
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

def sync_replies(rsa_cipher):
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
                    if str(data.get("client_number")) != CLIENT_NUMBER:
                        continue 

                    try:
                        encrypted_key = base64.b64decode(data['encrypted_session_key'])
                        session_key = rsa_cipher.decrypt(encrypted_key)
                        nonce = base64.b64decode(data['nonce'])
                        tag = base64.b64decode(data['tag'])
                        ciphertext = base64.b64decode(data['ciphertext'])
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                        decrypted_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
                        decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
                        data_to_log = decrypted_data
                        data_to_log['status'] = 'success'
                        
                        reply_json_string = json.dumps(data_to_log, indent=2)
                        log_to_csv(REPLY_CSV_LOG, data_to_log, ["uuid", "command", "time_replied", "status"])
                        log_file_path = os.path.join(REPLY_LOGS_DIR, f"reply_{command_uuid}.txt")
                        log_to_txt(log_file_path, reply_json_string)
                        processed_replies.add(command_uuid)
                        replies_synced += 1
                    except Exception as e:
                        print(f"DECRYPTION FAILED for reply with UUID {command_uuid[:8]}. Error: {e}")
                        failure_data = {"uuid": command_uuid, "command": "DECRYPTION_FAILED", "status": "failed"}
                        log_to_csv(REPLY_CSV_LOG, failure_data, ["uuid", "command", "time_replied", "status"])
                        processed_replies.add(command_uuid)
                        replies_synced += 1
                        continue

            except (json.JSONDecodeError, AttributeError):
                continue
        
        print(f"\nSync complete. Fetched and logged {replies_synced} new replies.")
        mail.close()
        mail.logout()
    except Exception as e:
        print(f"An error occurred while syncing replies: {e}")

def view_logs_paginated():
    print("\n--- View Command Logs ---")
    try:
        with open(SENT_CSV_LOG, 'r', newline='') as f:
            reader = csv.DictReader(f)
            all_logs = list(reader)[::-1]
    except FileNotFoundError:
        print("No logs found. Send a command first.")
        return

    page_size = 10
    current_page = 0
    total_pages = (len(all_logs) + page_size - 1) // page_size

    while True:
        print(f"\n--- Sent Commands (Page {current_page + 1}/{total_pages}) ---")
        start_index = current_page * page_size
        logs_for_page = all_logs[start_index:start_index + page_size]

        for i, log in enumerate(logs_for_page, start=1):
            time_str = log.get('time_sent', '')
            display_time = time_str[:19] if time_str else "N/A"
            print(f"  {i}. [{display_time}] Srv:{log.get('server_number')} CMD: \"{log.get('command')}\" UUID: {log.get('uuid', '')[:8]}...")
        
        print("\nOptions: (N)ext, (P)revious, (Enter a number to view details), (Q)uit")
        action = input("Enter action: ").lower()

        if action == 'n':
            if current_page < total_pages - 1: current_page += 1
        elif action == 'p':
            if current_page > 0: current_page -= 1
        elif action == 'q':
            break
        else:
            try:
                selection = int(action)
                if 1 <= selection <= len(logs_for_page):
                    selected_uuid = logs_for_page[selection - 1].get('uuid')
                    display_log_details(selected_uuid)
            except (ValueError, IndexError):
                print("Invalid action.")

def display_log_details(uuid_to_find):
    sent_log_path = os.path.join(SENT_LOGS_DIR, f"sent_{uuid_to_find}.txt")
    reply_log_path = os.path.join(REPLY_LOGS_DIR, f"reply_{uuid_to_find}.txt")
    
    if os.path.exists(sent_log_path):
        with open(sent_log_path, 'r') as f:
            print("\n--- Sent Command Details ---\n" + f.read())
    
    if os.path.exists(reply_log_path):
        with open(reply_log_path, 'r') as f:
            print("\n--- Received Reply Details ---\n" + f.read())
            
    if not os.path.exists(sent_log_path) and not os.path.exists(reply_log_path):
        print(f"No detailed .txt logs found for UUID {uuid_to_find}.")

def interactive_mode(server_keys, reply_cipher):
    setup_logging()
    print("--- Mail Commander (Secure Multi-Server Mode) ---")
    
    while True:
        print("\nAvailable actions: [send], [sync] replies, [read] logs, [quit]")
        action = input("Enter action: ").lower()

        if action == 'send':
            if not server_keys:
                print("Cannot send command: No server public keys loaded.")
                continue
            send_command_email(server_keys)
        elif action == 'sync':
            if not reply_cipher:
                 print("Cannot sync replies: Client private key not loaded.")
                 continue
            sync_replies(reply_cipher)
        elif action == 'read':
            view_logs_paginated()
        elif action == 'quit':
            break
        else:
            print("Invalid action.")

if __name__ == "__main__":
    if not all([USERNAME, PASSWORD, SMTP_SERVER, IMAP_SERVER, CLIENT_NUMBER]):
        print("Error: Ensure .env file has EMAIL_USERNAME, EMAIL_PASSWORD, SMTP_SERVER, IMAP_SERVER, and CLIENT_NUMBER.")
    else:
        server_keys = load_server_public_keys()
        
        reply_rsa_cipher = None
        try:
            private_key = RSA.import_key(open(CLIENT_PRIVATE_KEY_PATH).read())
            reply_rsa_cipher = PKCS1_OAEP.new(private_key)
            print(f"Client private key loaded from {CLIENT_PRIVATE_KEY_PATH}.")
        except FileNotFoundError:
            print(f"WARNING: Client private key not found at '{CLIENT_PRIVATE_KEY_PATH}'. Cannot decrypt replies.")

        interactive_mode(server_keys, reply_rsa_cipher)