Mail Shell: A Secure, Email-Based Remote Administration Tool

Mail Shell is a Python-based client-server system that allows you to securely execute commands on a remote machine using email as the transport layer.

Born from the challenge of managing a remote machine without opening traditional network ports like SSH, this project provides a robust and asynchronous way to stay in control of your devices. The entire system is built with a security-first mindset, featuring an end-to-end hybrid encryption model to ensure that all communications are confidential and tamper-proof.
Core Features

    End-to-End Hybrid Encryption: Commands and replies are secured using a professional-grade hybrid encryption model (RSA-2048 for key exchange and AES for data), protecting against eavesdropping and ensuring message integrity.

    Asynchronous Communication: Leverages universal email protocols (IMAP and SMTP) to create a resilient, asynchronous communication channel that doesn't require a constant, direct network connection.

    Multi-Client & Multi-Server Architecture: Designed to scale. A single server can manage commands from multiple, distinct clients, and a single client can manage multiple servers, with each entity identified by a unique numerical ID and key pair.

    Interactive Command-Line Client: A user-friendly CLI allows you to intuitively send commands, sync encrypted replies, and browse a paginated history of all communications.

    Robust Logging & Tracking: All operations are tracked using universally unique identifiers (UUIDs). Both the client and server maintain detailed logs of commands sent, replies received, and any system errors.

How It Works

The system operates in a secure, asynchronous loop:

    Client: The client generates a command, identifies itself with its CLIENT_NUMBER, and encrypts the payload using hybrid encryption with the target SERVER_NUMBER's public key.

    Send: The encrypted payload is sent as a JSON object in the body of an email.

    Server: The server polls the email inbox every 15 minutes, looking for new command emails.

    Process: Upon finding a new command, the server checks if it's for the correct SERVER_NUMBER, decrypts the payload with its private key, and verifies it's from a trusted CLIENT_NUMBER.

    Execute & Reply: The server executes the command, captures the output, and encrypts the full reply using the original client's public key.

    Sync: The client can sync at any time to fetch, decrypt, and log the replies meant for it.

Getting Started
1. Prerequisites

    Python 3.6+

    A dedicated email account (e.g., Gmail) with an App Password. Do not use your regular password.

2. Installation

Clone the repository and install the required Python libraries:

git clone [https://github.com/your-username/mail-shell.git](https://github.com/your-username/mail-shell.git)
cd mail-shell
pip install pycryptodome python-dotenv

3. Generate Keys

This system uses a separate key pair for each client and server. Run the provided key generation script:

python generate_keys.py

Follow the prompts to specify how many server and client key pairs you need. This will create a generated_keys directory with server_config and client_config subfolders containing all your keys, correctly named and placed.
4. Configuration

    Move the server_config folder to your server machine and the client_config folder to your client machine.

    In both the client and server root directories, create a .env file by copying the .env.example.

    Fill out the .env files with your email credentials and the correct SERVER_NUMBER or CLIENT_NUMBER.

Usage

    To run the server:

    # Navigate to the server's src directory
    python continuous_email_checker.py

    To run the client:

    # Navigate to the client's src directory
    python mail_sender_cli.py

    The client will start in interactive mode with the following commands: send, sync, read, and quit.

🚨 Security Warning

This tool is designed to execute arbitrary commands on your system. Even with end-to-end encryption, this is an incredibly powerful and potentially dangerous capability. For a production-ready system, the next critical security step is to implement a strict command whitelist on the server to ensure that only pre-approved, safe commands can ever be executed.

Use this tool responsibly and at your own risk.
Roadmap (Future Capabilities)

    [x] ~~Encryption~~ (Done!)

    [x] ~~Multi-Client/Multi-Server Support~~ (Done!)

    [ ] Command Whitelisting: Implement a strict safelist of allowed commands on the server.

    [ ] Digital Signatures: Add a signature to commands to protect against replay attacks and verify sender identity, in addition to encryption.

    [ ] Android Client: Develop a simple client for mobile management.

    [ ] Attachment Support: Allow the server to send back files (e.g., log files, screenshots) as encrypted email attachments.