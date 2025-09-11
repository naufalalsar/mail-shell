# **Mail Shell** : A Secure Way to Execute Commands via Email

This personal project started from a problem that i had. That problem being "how can i connect my moving laptop with my personal computer on home?". So naturally the answer to that problem i change my internet plan to include static ip which is quite expensive (and quite a pain to set up). Or, i can use Virtual Private Server (VPS) to connect my laptop and personal computer using Virtual Private Network (VPN) but this also requires money. So i think that using email could work to connect my laptop and my computer. Ofcourse this itself has quite a problem, this is the list of the problem that i have indentified : 

1. Content would be exposed which made it easy for someone to control over my computer if they breach my email (i mean i guess you could also count the Email Service Provider (ESP) as the potential breacher).

2. Largely would be asynchronous, synchronous could be achieved but it would make you hit the quota from ESP pretty fast (then again why don't you use VPS and connect it using VPN for that instead, as essentialy it's the same thing?).

Mail Shell is the result of that problem. It is a complete, Python-based client-server system that enables remote command execution over a secure, asynchronous, and end-to-end encrypted channel. It uses standard email protocols (IMAP/SMTP) as a transport layer.

## The Core Concept

The system operates on this premise: the client sends an email containing an encrpyed command, and the server polls the email account, processes the command, and sends an encrypted reply. 

## Security Overview

* **Confidentiality:** All commands and replies are protected by RSA + AES, ensuring that messages of any size remain secret and unreadable to eavesdroppers.

* **Authentication:** To prevent impersonation, every message is protected by a digital signature. The server can mathematically verify the identity of the sender, ensuring that only trusted clients can issue commands.

* **Integrity:** The system uses an authenticated encryption mode (AEAD) which generates a cryptographic tag. This acts as a tamper-proof seal, guaranteeing that the message has not been altered in any way during transit.

* **Replay Protection:** Every command is assigned a unique UUID that is included in the signature. The server maintains a log of all processed commands and will reject any duplicates, making it immune to replay attacks.

## Features

* **End-to-End Encryption:** Full confidentiality for all commands and replies.

* **Multi-Client & Multi-Server Architecture:** Securely manage multiple servers from multiple, distinct clients, with each entity having its own unique cryptographic identity.

* **Asynchronous Communication:** No open ports required on the server and client.

* **Robust Logging:** Detailed client- and server-side logging for auditing and debugging, including both high-level CSV summaries and detailed per-command .txt logs.

## Getting Started

All of the code can be accessed on src folder.

1. Prerequisites

    First, install the necessary Python libraries:

    `pip install pycryptodome python-dotenv`

2. Generate Your Keys

    The system requires two key pairs: one for the server and one for each client. The generate_keys.py script automates this process.

    Run the script from your terminal: `python generate_keys.py`

    Follow the prompts, telling it how many server and client key pairs you need.

    The script will create a generated_keys folder containing server and client subdirectories with all your keys correctly named and placed.

3. Configure Your Environment

    Open the generated_keys folder.

    Move the entire server folder content to your server machine (same level as main_encrpytion.py script).

    Move the entire client folder content to your client machine (same level as main_encrpytion.py script).

    Inside each folder, create a .env file. You can copy .env.example to get started.

    Example .env for the server:

    `EMAIL_USERNAME=your_email@gmail.com
    EMAIL_PASSWORD=your-16-character-app-password
    EMAIL_SERVER=imap.gmail.com
    SMTP_SERVER=smtp.gmail.com
    SERVER_NUMBER=1`

    Example .env for the client:

    `EMAIL_USERNAME=your_email@gmail.com
    EMAIL_PASSWORD=your-16-character-app-password
    EMAIL_SERVER=imap.gmail.com
    SMTP_SERVER=smtp.gmail.com
    CLIENT_NUMBER=1`

4. Run the Application

    On the server machine, navigate into the server directory and run:

    `python main_encrpytion.py`

    On the client machine, navigate into the client directory and run:

    `python main_encrpytion.py`

## Client Usage

The interactive client provides a simple menu:

    - send: Guides you through sending a new encrypted and signed command.

    - sync: Fetches and securely decrypts any new replies from the server.

    - read: Opens a paginated log viewer to review the history of your sent commands and their replies.

    - quit: Exits the application.

## The Unencrypted Version

    ⚠️ Security Warning: This project also includes separate, unencrypted versions of the client and server scripts. These are provided strictly for educational and testing purposes. They are fundamentally insecure and should NEVER be used in a real-world environment, as they transmit executable commands in plaintext.

## Roadmap & Future Work

Future versions could include:

    Command Whitelisting: A server-side configuration to restrict which commands are allowed to be executed.

    Android Support: A dedicated client app for managing servers from a mobile device.