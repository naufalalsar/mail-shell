Example command : 

{
  "command": "echo Hello World",
  "time_sent": "2025-09-02T18:51:00Z",
  "uuid": "c78090dd-86a9-4631-80c2-fc3cd162015e",
  "server_number": 1
}

Example reply : 

{
  "command": "echo Hello World",
  "time_sent": "2025-09-02T18:51:00Z",
  "uuid": "c78090dd-86a9-4631-80c2-fc3cd162015e",
  "server_number": 1,
  "command_reply": "Hello World",
  "time_replied": "2025-09-02T18:52:30Z"
}

Example encrypted command : 

{
  "uuid": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "server_number": 1,
  "client_number": 1,
  "encrypted_session_key": "...",
  "nonce": "...",
  "tag": "...",
  "ciphertext": "..."
}

Decrpyed :

{
  "command": "dir",
  "time_sent": "2025-09-11T13:45:00Z",
  "client_number": 1
}

Example encrypted reply : 

{
  "uuid": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "server_number": 1,
  "client_number": 1,
  "encrypted_session_key": "...",
  "nonce": "...",
  "tag": "...",
  "ciphertext": "..."
}

Decrpyed :

{
  "uuid": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "command": "dir",
  "time_sent": "2025-09-11T13:45:00Z",
  "command_reply": [
    " Volume in drive C has no label.",
    " Volume Serial Number is 1234-5678",
    "",
    " Directory of C:\\Users\\YourUser\\Projects\\MailShell\\server",
    "",
    "09/11/2025  01:45 PM    <DIR>          .",
    "09/11/2025  01:45 PM    <DIR>          ..",
    "09/11/2025  01:30 PM             8,192 continuous_email_checker.py",
    "..."
  ],
  "server_number": 1,
  "time_replied": "2025-09-11T13:46:15.123456"
}
