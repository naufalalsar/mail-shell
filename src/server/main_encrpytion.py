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
SERVER_PRIVATE_KEY_PATH = os.getenv("SERVER_PRIVATE_KEY_PATH", "server_private.pem")
CLIENT_PUBLIC_KEY_PATH = os.getenv("CLIENT_PUBLIC_KEY_PATH", "client_public.pem")

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

def send_reply_email(original_data, command_output, rsa_cipher):
    command_uuid = original_data.get("uuid")
    try:
        inner_reply_data = {
            "uuid": command_uuid,
            "command": original_data.get("command"),
            "time_sent": original_data.get("time_sent"),
            "command_reply": command_output,
            "server_number": int(SERVER_NUMBER),
            "time_replied": datetime.now().isoformat()
        }

        log_command_activity(command_uuid, "Encrypting reply using hybrid encryption (AES+RSA)...")
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
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
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
        
        log_command_activity(command_uuid, f"Successfully sent hybrid encrypted reply.")

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

def check_emails(processed_uuids, decrypt_cipher, reply_cipher):
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
                    
                    # --- MODIFICATION: Check for hybrid encryption fields ---
                    if not all(k in data for k in ["encrypted_session_key", "nonce", "tag", "ciphertext"]):
                        log_command_activity(command_uuid, "Skipping: command is not in the expected hybrid encrypted format.")
                        log_to_csv(data, "rejected_unencrypted")
                        processed_uuids.add(command_uuid)
                        continue
                    
                    try:
                        log_command_activity(command_uuid, "Decrypting hybrid payload...")
                        
                        encrypted_session_key = base64.b64decode(data['encrypted_session_key'])
                        nonce = base64.b64decode(data['nonce'])
                        tag = base64.b64decode(data['tag'])
                        ciphertext = base64.b64decode(data['ciphertext'])

                        session_key = decrypt_cipher.decrypt(encrypted_session_key)
                        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                        decrypted_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag)

                        decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
                        decrypted_data['uuid'] = command_uuid
                        data = decrypted_data
                    except Exception as e:
                        log_command_activity(command_uuid, f"DECRYPTION FAILED. Error: {e}")
                        log_to_csv({"uuid": command_uuid}, "failed_decryption")
                        processed_uuids.add(command_uuid)
                        continue
                    
                    server_num = data.get("server_number")
                    if str(server_num) != SERVER_NUMBER:
                        log_command_activity(command_uuid, f"Skipping: for server #{server_num}.")
                        continue
                    
                    command = data.get("command")
                    if command:
                        output = execute_command(command, command_uuid)
                        send_reply_email(data, output, reply_cipher)
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
        print("Encryption is REQUIRED for this script.")
        try:
            private_key = RSA.import_key(open(SERVER_PRIVATE_KEY_PATH).read())
            decrypt_cipher = PKCS1_OAEP.new(private_key)
            print(f"Server private key loaded from {SERVER_PRIVATE_KEY_PATH}.")
        except FileNotFoundError:
            print(f"FATAL ERROR: Server private key not found at '{SERVER_PRIVATE_KEY_PATH}'.")
            exit()
        
        try:
            public_key = RSA.import_key(open(CLIENT_PUBLIC_KEY_PATH).read())
            reply_cipher = PKCS1_OAEP.new(public_key)
            print(f"Client public key loaded from {CLIENT_PUBLIC_KEY_PATH}.")
        except FileNotFoundError:
            print(f"FATAL ERROR: Client public key not found at '{CLIENT_PUBLIC_KEY_PATH}'. Cannot encrypt replies.")
            exit()

        setup_logging()
        processed_uuids = load_processed_uuids()
        print(f"Starting email checker for server #{SERVER_NUMBER}. Loaded {len(processed_uuids)} commands.")
        print("Press Ctrl+C to stop.")
        while True:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n--- [{current_time}] Checking for emails ---")
            check_emails(processed_uuids, decrypt_cipher, reply_cipher)
            wait_time = 15 * 60
            print(f"--- Check complete. Waiting for {wait_time / 60} minutes... ---")
            time.sleep(wait_time)