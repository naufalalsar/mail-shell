import os
from Crypto.PublicKey import RSA

def get_positive_integer(prompt):
    """Gets a positive integer from the user."""
    while True:
        try:
            value = int(input(prompt))
            if value > 0:
                return value
            else:
                print("Please enter a number greater than 0.")
        except ValueError:
            print("Invalid input. Please enter a whole number.")

def generate_and_save_keys(key_type, count, private_key_dir, public_key_dir):
    """Generates a specified number of key pairs and saves them to the correct directories."""
    print(f"\n--- Generating {count} {key_type} key pair(s) ---")
    for i in range(1, count + 1):
        print(f"Generating key pair for {key_type} {i}...")
        key = RSA.generate(2048)

        # Define file paths for the keys
        private_key_path = os.path.join(private_key_dir, f"{i}_private.pem")
        public_key_path = os.path.join(public_key_dir, f"{i}.pem")

        # Export and save private key
        private_key_pem = key.export_key()
        with open(private_key_path, "wb") as f:
            f.write(private_key_pem)
        print(f"  - Saved private key to: {private_key_path}")
        
        # Export and save public key
        public_key_pem = key.publickey().export_key()
        with open(public_key_path, "wb") as f:
            f.write(public_key_pem)
        print(f"  - Saved public key to:  {public_key_path}")

if __name__ == "__main__":
    # --- Get User Input ---
    num_servers = get_positive_integer("How many SERVER key pairs do you want to generate? ")
    num_clients = get_positive_integer("How many CLIENT key pairs do you want to generate? ")

    # --- Define Directory Structure ---
    root_dir = "generated_keys"
    server_dir = os.path.join(root_dir, "server")
    client_dir = os.path.join(root_dir, "client")
    server_trusted_clients_dir = os.path.join(server_dir, "trusted_clients")
    client_server_keys_dir = os.path.join(client_dir, "server_keys")

    # --- Create Directories ---
    os.makedirs(server_trusted_clients_dir, exist_ok=True)
    os.makedirs(client_server_keys_dir, exist_ok=True)
    print("\nCreated directory structure inside 'generated_keys':")
    print(f"- {os.path.basename(server_dir)}/")
    print(f"  - {os.path.basename(server_trusted_clients_dir)}/")
    print(f"- {os.path.basename(client_dir)}/")
    print(f"  - {os.path.basename(client_server_keys_dir)}/")

    # --- Generate Keys ---
    # Server keys: private keys go in the main server folder, public keys go to the client's server_keys folder
    generate_and_save_keys("Server", num_servers, server_dir, client_server_keys_dir)
    
    # Client keys: private keys go in the main client folder, public keys go to the server's trusted_clients folder
    generate_and_save_keys("Client", num_clients, client_dir, server_trusted_clients_dir)
    
    # --- Final Instructions ---
    print("\n" + "="*40)
    print("Key generation complete!")
    print("\n--- NEXT STEPS ---")
    print(f"1. Open the '{root_dir}' folder.")
    print(f"2. Move the entire '{os.path.basename(server_dir)}' folder to your server machine and rename it as you see fit.")
    print(f"3. Move the entire '{os.path.basename(client_dir)}' folder to your client machine and rename it.")
    print("4. Ensure your .env files are updated with the correct CLIENT_ID and SERVER_NUMBER.")
    print("="*40)