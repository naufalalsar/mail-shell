import imaplib
import email
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
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# --- Load environment variables from .env file ---
load_dotenv()

# --- Load All Configuration from .env ---
USERNAME = os.getenv("EMAIL_USERNAME")
PASSWORD = os.getenv("EMAIL_PASSWORD")
SERVER = os.getenv("EMAIL_SERVER")
SERVER_NUMBER = os.getenv("SERVER_NUMBER")
SMTP_SERVER = os.getenv("SMTP_SERVER")

# --- Encryption Configuration ---
SERVER_PRIVATE_KEY_PATH = f"{SERVER_NUMBER}_private.pem"
CLIENT_KEYS_DIR = "trusted_clients"

# --- Log File Configuration ---
LOGS_DIR = "logs"
CSV_LOG_FILE = os.path.join(LOGS_DIR, "executed_commands.csv")

def load_trusted_client_keys():
    """Loads client public keys, mapping filenames like "1.pem" to integer ID 1."""
    keys = {}
    print(f"Loading trusted client keys from '{CLIENT_KEYS_DIR}'...")
    try:
        if not os.path.isdir(CLIENT_KEYS_DIR):
            print(f"Warning: Directory for trusted client keys not found at '{CLIENT_KEYS_DIR}'. Cannot encrypt replies.")
            return {}
        
        for filename in os.listdir(CLIENT_KEYS_DIR):
            if filename.endswith(".pem"):
                client_id_str = os.path.splitext(filename)[0]
                filepath = os.path.join(CLIENT_KEYS_DIR, filename)
                try:
                    client_number = int(client_id_str)
                    public_key = RSA.import_key(open(filepath).read())
                    keys[client_number] = PKCS1_OAEP.new(public_key)
                    print(f"  - Loaded key for client number: {client_number}")
                except (ValueError, Exception) as e:
                    print(f"  - Failed to load key from {filename}. Ensure it is named like '1.pem', '2.pem', etc. Error: {e}")
        return keys
    except Exception as e:
        print(f"An error occurred loading client keys: {e}")
        return {}

def setup_logging():
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(CSV_LOG_FILE):
        with open(CSV_LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["uuid", "command", "time_sent", "status", "client_number"])

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

def log_to_csv(data, status, client_number="unknown"):
    with open(CSV_LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([data.get('uuid'), data.get('command', 'N/A'), data.get('time_sent', 'N/A'), status, client_number])

def send_reply_email(original_data, command_output, rsa_cipher):
    command_uuid = original_data.get("uuid")
    try:
        inner_reply_data = {
            "uuid": command_uuid, "command": original_data.get("command"),
            "time_sent": original_data.get("time_sent"), "command_reply": command_output,
            "server_number": int(SERVER_NUMBER), "time_replied": datetime.now().isoformat()
        }
        log_command_activity(command_uuid, "Encrypting reply...")
        inner_json_bytes = json.dumps(inner_reply_data).encode('utf-8')
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(inner_json_bytes)
        encrypted_session_key = rsa_cipher.encrypt(session_key)
        final_payload_to_send = {
            "uuid": command_uuid,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
            "nonce": base64.b64encode(cipher_aes.nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "server_number": int(SERVER_NUMBER),
            "client_number": original_data.get("client_number")
        }
        reply_json_string = json.dumps(final_payload_to_send, indent=2)
        msg = EmailMessage()
        msg['Subject'] = "MAIL SHELL REPLY"
        msg['From'] = USERNAME
        msg['To'] = USERNAME
        msg.set_content(reply_json_string)
        with smtplib.SMTP(SMTP_SERVER, 587) as server:
            server.starttls()
            server.login(USERNAME, PASSWORD)
            server.send_message(msg)
        log_command_activity(command_uuid, "Successfully sent hybrid encrypted reply.")
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
        error_message = f"An error occurred: {e}"
        log_command_activity(command_uuid, error_message)
        return [error_message]

def check_emails(processed_uuids, decrypt_cipher, trusted_clients):
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
                    outer_data = json.loads(body)
                    command_uuid = outer_data.get("uuid")
                    target_server = outer_data.get("server_number")
                    client_number = outer_data.get("client_number")

                    if not command_uuid or command_uuid in processed_uuids:
                        continue
                    
                    if str(target_server) != SERVER_NUMBER:
                        continue
                    
                    if not client_number or client_number not in trusted_clients:
                        log_command_activity(command_uuid, f"REJECTED: Command from unknown/untrusted client number '{client_number}'.")
                        log_to_csv({"uuid": command_uuid, "client_number": client_number}, "rejected_untrusted_client", client_number)
                        processed_uuids.add(command_uuid)
                        continue

                    try:
                        encrypted_key = base64.b64decode(outer_data['encrypted_session_key'])
                        session_key = decrypt_cipher.decrypt(encrypted_key)
                        nonce = base64.b64decode(outer_data['nonce'])
                        tag = base64.b64decode(outer_data['tag'])
                        ciphertext = base64.b64decode(outer_data['ciphertext'])
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                        decrypted_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)
                        data = json.loads(decrypted_bytes.decode('utf-8'))
                        data['uuid'] = command_uuid
                        data['client_number'] = client_number
                    except Exception as e:
                        log_command_activity(command_uuid, f"DECRYPTION FAILED. Error: {e}")
                        log_to_csv({"uuid": command_uuid}, "failed_decryption", client_number)
                        processed_uuids.add(command_uuid)
                        continue
                    
                    command = data.get("command")
                    if command:
                        reply_cipher = trusted_clients[client_number]
                        output = execute_command(command, command_uuid)
                        send_reply_email(data, output, reply_cipher)
                        log_to_csv(data, "executed", client_number)
                        processed_uuids.add(command_uuid)
                        print(f"Processed command from client #{client_number} (UUID {command_uuid[:8]}...).")
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
        try:
            private_key = RSA.import_key(open(SERVER_PRIVATE_KEY_PATH).read())
            decrypt_cipher = PKCS1_OAEP.new(private_key)
            print(f"Server private key loaded from {SERVER_PRIVATE_KEY_PATH}.")
        except FileNotFoundError:
            print(f"FATAL ERROR: Server private key not found at '{SERVER_PRIVATE_KEY_PATH}'.")
            exit()
        
        trusted_clients = load_trusted_client_keys()
        if not trusted_clients:
            print("WARNING: No trusted client keys were loaded. Cannot send encrypted replies.")

        setup_logging()
        processed_uuids = load_processed_uuids()
        print(f"Starting email checker for server #{SERVER_NUMBER}. Loaded {len(processed_uuids)} commands.")
        print("Press Ctrl+C to stop.")
        while True:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n--- [{current_time}] Checking for emails ---")
            check_emails(processed_uuids, decrypt_cipher, trusted_clients)
            wait_time = 15 * 60
            print(f"--- Check complete. Waiting for {wait_time / 60} minutes... ---")
            time.sleep(wait_time)