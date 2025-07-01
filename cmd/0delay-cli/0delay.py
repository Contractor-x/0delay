#!/usr/bin/env python3
import os
import sys
import json
import getpass
import paramiko
import base64
from pathlib import Path

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

import json

CONFIG_FILE = Path(__file__).parent.parent.parent / "configs" / "config.json"

ASCII_ART = r"""
  ____   ____       _       _             
 |  _ \ |  _ \     | |     | |            
 | | | || | | | ___| | __ _| |_ ___  _ __ 
 | | | || | | |/ _ \ |/ _` | __/ _ \| '__|
 | |_| || |_| |  __/ | (_| | || (_) | |   
 |____/ |____/ \___|_|\__,_|\__\___/|_|   
                                          
"""

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def prompt_for_config():
    print(ASCII_ART)
    config = load_config()

    # Show username if available
    username = config.get("username")
    if username:
        print(f"Current username: {username}")

    print("Welcome to 0delay - Linux Transfer System")

    # Load or initialize pem keys dictionary
    pem_keys = config.get("pem_keys", {})

    # Load or initialize transfer history list
    transfer_history = config.get("transfer_history", [])

    # Prompt for public IP or username@ip
    if "last_target" in config:
        print(f"Last target: {config['last_target']}")
        use_saved = input("Use last target? (y/n): ").strip().lower()
        if use_saved == "y":
            target = config["last_target"]
        else:
            target = input("Enter target (username@ip or public IP): ").strip()
    else:
        target = input("Enter target (username@ip or public IP): ").strip()

    # Parse target into username and ip
    if "@" in target:
        username, public_ip = target.split("@", 1)
    else:
        username = None
        public_ip = target

    # Select or add pem key
    if pem_keys:
        print("Saved PEM keys:")
        for i, key_name in enumerate(pem_keys.keys()):
            print(f"{i+1}. {key_name}")
        choice = input("Select PEM key by number or enter 'n' to add new: ").strip()
        if choice.lower() == "n":
            key_name = input("Enter name for new PEM key: ").strip()
            key_path = input("Enter path to PEM key file: ").strip()
            if not os.path.isfile(key_path):
                print("Error: PEM key file not found.")
                sys.exit(1)
            pem_keys[key_name] = key_path
        else:
            try:
                idx = int(choice) - 1
                key_name = list(pem_keys.keys())[idx]
                key_path = pem_keys[key_name]
            except:
                print("Invalid selection.")
                sys.exit(1)
    else:
        key_name = input("Enter name for PEM key: ").strip()
        key_path = input("Enter path to PEM key file: ").strip()
        if not os.path.isfile(key_path):
            print("Error: PEM key file not found.")
            sys.exit(1)
        pem_keys[key_name] = key_path

    # Save updated config
    config["public_ip"] = public_ip
    config["username"] = username
    config["pem_keys"] = pem_keys
    config["last_target"] = target
    config["transfer_history"] = transfer_history
    save_config(config)

    return config

def pick_file():
    print("\nPlease enter the full path of the file you want to send:")
    while True:
        file_path = input("File path: ").strip()
        if os.path.isfile(file_path):
            return file_path
        else:
            print("File not found. Please enter a valid file path.")

def hamming_encode(data):
    # Simple Hamming(7,4) code implementation for error correction
    # For demonstration, encode data bytes in chunks of 4 bits
    encoded_bytes = bytearray()
    for byte in data:
        # Split byte into two 4-bit halves
        high_nibble = (byte >> 4) & 0x0F
        low_nibble = byte & 0x0F
        encoded_bytes.append(encode_nibble(high_nibble))
        encoded_bytes.append(encode_nibble(low_nibble))
    return bytes(encoded_bytes)

def encode_nibble(nibble):
    # Hamming(7,4) encoding for 4 bits
    d = [(nibble >> i) & 1 for i in range(4)]
    p1 = d[0] ^ d[1] ^ d[3]
    p2 = d[0] ^ d[2] ^ d[3]
    p3 = d[1] ^ d[2] ^ d[3]
    # Arrange bits: p1 p2 d0 p3 d1 d2 d3
    encoded = (p1 << 6) | (p2 << 5) | (d[0] << 4) | (p3 << 3) | (d[1] << 2) | (d[2] << 1) | d[3]
    return encoded

def encrypt_data(data, password=None):
    if password:
        password_bytes = password.encode()
        salt = os.urandom(16)
        # Derive key using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password_bytes)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)
        # Return salt + nonce + encrypted data for decryption
        return salt + nonce + encrypted
    else:
        return data

def ssh_send_file(config, file_path, password=None):
    public_ip = config["public_ip"]
    pem_key_path = config["pem_key_path"]
    username = "ec2-user"  # Default username for EC2, could be made configurable

    # Read private key
    try:
        key = paramiko.RSAKey.from_private_key_file(pem_key_path)
    except Exception as e:
        print(f"Failed to load private key: {e}")
        return False

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Connecting to {public_ip}...")
        ssh.connect(public_ip, username=username, pkey=key)
        sftp = ssh.open_sftp()
        # Read file data
        with open(file_path, "rb") as f:
            data = f.read()
        # Encode with Hamming code
        encoded_data = hamming_encode(data)
        # Encrypt data if password provided
        encrypted_data = encrypt_data(encoded_data, password)
        # Write to remote file
        remote_path = f"/home/{username}/received_file"
        with sftp.file(remote_path, "wb") as remote_file:
            remote_file.write(encrypted_data)
        print(f"File sent successfully to {remote_path} on {public_ip}")
        sftp.close()
        ssh.close()
        return True
    except Exception as e:
        print(f"Failed to send file: {e}")
        return False

def main():
    config = prompt_for_config()
    print(f"Configuration saved. Ready to send files to {config['public_ip']}.")
    file_to_send = pick_file()
    print(f"Selected file: {file_to_send}")
    use_password = input("Do you want to protect the file with a password? (y/n): ").strip().lower()
    password = None
    if use_password == "y":
        password = getpass.getpass("Enter password: ")
    success = ssh_send_file(config, file_to_send, password)
    if success:
        print("File transfer completed successfully.")
    else:
        print("File transfer failed.")

if __name__ == "__main__":
    main()
