from Crypto.PublicKey import RSA

# --- Generate Server Keys ---
print("Generating SERVER key pair (2048 bit)...")
server_key = RSA.generate(2048)

# Export server private key
server_private_key = server_key.export_key()
with open("server_private.pem", "wb") as f:
    f.write(server_private_key)
print("Successfully created server_private.pem")

# Export server public key
server_public_key = server_key.publickey().export_key()
with open("server_public.pem", "wb") as f:
    f.write(server_public_key)
print("Successfully created server_public.pem")

print("\n" + "-"*30 + "\n")

# --- Generate Client Keys ---
print("Generating CLIENT key pair (2048 bit)...")
client_key = RSA.generate(2048)

# Export client private key
client_private_key = client_key.export_key()
with open("client_private.pem", "wb") as f:
    f.write(client_private_key)
print("Successfully created client_private.pem")

# Export client public key
client_public_key = client_key.publickey().export_key()
with open("client_public.pem", "wb") as f:
    f.write(client_public_key)
print("Successfully created client_public.pem")

print("\nKey generation complete. All four key files have been created.")
print("\n--- Next Steps ---")
print("1. Copy 'server_private.pem' and 'client_public.pem' to your SERVER directory.")
print("2. Copy 'client_private.pem' and 'server_public.pem' to your CLIENT directory.")

