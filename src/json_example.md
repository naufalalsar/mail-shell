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

Decrypted :

{
  "command": "dir",
  "time_sent": "2025-09-11T13:45:00Z",
  "client_number": 1,
  "uuid": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "server_number": 1
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

Decrypted :

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
    "09/11/2025  01:30 PM             8,192 main.py",
    "..."
  ],
  "server_number": 1,
  "time_replied": "2025-09-11T13:46:15.123456",
  "client_number": 1
}
