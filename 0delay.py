if i#!/usr/bin/env python3
import os
import sys
import json
import getpass
import paramiko
import base64
import socket
import threading
from pathlib import Path
from dotenv import load_dotenv

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from supabase import create_client, Client

CONFIG_FILE = Path.home() / ".0delay_config.json"
ASCII_ART = r"""                   ..                        ..                          
    .n~~%x.      dF                    x .d88"                ..         
  x88X   888.   '88bu.                  5888R                @L          
 X888X   8888L  '*88888bu        .u     '888R         u     9888i   .dL  
X8888X   88888    ^"*8888N    ud8888.    888R      us888u.  `Y888k:*888. 
88888X   88888X  beWE "888L :888'8888.   888R   .@88 "8888"   888E  888I 
88888X   88888X  888E  888E d888 '88%"   888R   9888  9888    888E  888I 
88888X   88888f  888E  888E 8888.+"      888R   9888  9888    888E  888I 
48888X   88888   888E  888F 8888L        888R   9888  9888    888E  888I 
 ?888X   8888"  .888N..888  '8888c. .+  .888B . 9888  9888   x888N><888' 
  "88X   88*`    `"888*""    "88888%    ^*888%  "888*""888"   "88"  888  
    ^"==="`         ""         "YP'       "%     ^Y"   ^Y'          88F  
                                                                   98"   
                                                                 ./"     
                                                                ~`       
"""

def load_env():
    load_dotenv("configs/.env")
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_ANON_KEY")
    if not supabase_url or not supabase_key:
        print("Supabase credentials not found in .env file.")
        sys.exit(1)
    return supabase_url, supabase_key

def create_supabase_client():
    url, key = load_env()
    client = create_client(url, key)
    return client

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # connect to a public DNS server to get local IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def register_user(supabase: Client, username: str, ip: str):
    # Register or update username and IP in single table "usernames"
    response = supabase.table("usernames").select("*").eq("username", username).execute()
    if response.data:
        if response.data[0]["ip"] != ip:
            supabase.table("usernames").update({"ip": ip}).eq("username", username).execute()
    else:
        supabase.table("usernames").insert({"username": username, "ip": ip}).execute()

def get_user_ip(supabase: Client, username: str):
    response = supabase.table("usernames").select("ip").eq("username", username).execute()
    if response.data:
        return response.data[0]["ip"]
    return None

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) != 0

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

def decrypt_data(encrypted_data, password):
    try:
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password_bytes)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

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

def linux_to_linux_send(supabase, username):
    # Get IP from supabase
    ip = get_user_ip(supabase, username)
    use_saved_ip = False
    if ip:
        use_saved = input(f"Use saved IP {ip}? (y/n): ").strip().lower()
        if use_saved == "y":
            use_saved_ip = True
    if not use_saved_ip:
        ip = input("Enter the IP address of the target Linux machine: ").strip()
        register_user(supabase, username, ip)
    print(f"Sending file to Linux machine at IP: {ip}")
    file_path = pick_file()
    use_password = input("Do you want to protect the file with a password? (y/n): ").strip().lower()
    password = None
    if use_password == "y":
        password = getpass.getpass("Enter password: ")
        # Encrypt file and save to temp file
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = encrypt_data(data, password)
        temp_file_path = file_path + ".enc"
        with open(temp_file_path, "wb") as f:
            f.write(encrypted_data)
        file_path_to_send = temp_file_path
    else:
        file_path_to_send = file_path
    # Use scp command for transfer
    scp_command = f"scp {file_path_to_send} {username}@{ip}:~/"
    print(f"Executing: {scp_command}")
    result = os.system(scp_command)
    if result == 0:
        print("File sent successfully.")
        if password == "y":
            os.remove(temp_file_path)
    else:
        print("File transfer failed.")

def handle_client_connection(client_socket, password=None):
    try:
        # Receive file size first (8 bytes)
        file_size_bytes = client_socket.recv(8)
        if len(file_size_bytes) < 8:
            print("Failed to receive file size.")
            return
        file_size = int.from_bytes(file_size_bytes, byteorder='big')
        received = 0
        chunks = []
        while received < file_size:
            chunk = client_socket.recv(min(4096, file_size - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
        file_data = b''.join(chunks)
        if password:
            file_data = decrypt_data(file_data, password)
            if file_data is None:
                print("Failed to decrypt file.")
                return
        # Save received file
        save_path = input("Enter path to save received file: ").strip()
        with open(save_path, "wb") as f:
            f.write(file_data)
        print(f"File saved to {save_path}")
    except Exception as e:
        print(f"Error receiving file: {e}")
    finally:
        client_socket.close()

def start_listening_mode(password=None):
    port = 8008 if is_port_open(8008) else 6475
    print(f"Listening for incoming transfers on port {port}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    try:
        while True:
            client_sock, addr = server.accept()
            print(f"Connection from {addr}")
            client_thread = threading.Thread(target=handle_client_connection, args=(client_sock, password))
            client_thread.start()
    except KeyboardInterrupt:
        print("Stopping listening mode.")
    finally:
        server.close()

def prompt_for_config():
    print(ASCII_ART)
    print("Welcome to 0Delay - Linux based Transfer System")
    config = load_config()
    if "username" in config:
        print(f"Current saved username: {config['username']}")
        use_saved = input("Use saved username? (y/n): ").strip().lower()
        if use_saved == "y":
            username = config["username"]
        else:
            username = input("Enter your username: ").strip()
    else:
        username = input("Enter your username: ").strip()

    if "public_ip" in config:
        print(f"Current saved public IP: {config['public_ip']}")
        use_saved = input("Use saved public IP? (y/n): ").strip().lower()
        if use_saved == "y":
            public_ip = config["public_ip"]
        else:
            public_ip = input("Enter the public IP to send files to: ").strip()
    else:
        public_ip = input("Enter the public IP to send files to: ").strip()

    if "pem_key_path" in config:
        print(f"Current saved .pem key path: {config['pem_key_path']}")
        use_saved = input("Use saved .pem key path? (y/n): ").strip().lower()
        if use_saved == "y":
            pem_key_path = config["pem_key_path"]
        else:
            pem_key_path = input("Enter the path to your .pem key file: ").strip()
    else:
        pem_key_path = input("Enter the path to your .pem key file: ").strip()

    # Validate pem key path if provided
    while pem_key_path and not os.path.isfile(pem_key_path):
        print("Error: .pem key file not found.")
        pem_key_path = input("Please enter a valid path to your .pem key file: ").strip()

    config = {
        "username": username,
        "public_ip": public_ip,
        "pem_key_path": pem_key_path
    }
    save_config(config)
    return config

def main():
    supabase = create_supabase_client()
    config = prompt_for_config()
    register_user(supabase, config["username"], config["public_ip"])

    print("Select mode:")
    print("1. Linux to Linux file transfer")
    print("2. Linux to EC2 file transfer")
    print("3. Listening mode (receive files)")
    mode = input("Enter mode number: ").strip()

    if mode == "1":
        linux_to_linux_send(supabase, config["username"])
    elif mode == "2":
        file_to_send = pick_file()
        use_password = input("Do you want to protect the file with a password? (y/n): ").strip().lower()
        password = None
        if use_password == "y":
            password = getpass.getpass("Enter password: ")
        success = ssh_send_file(config, file_to_send, password)
        if success:
            print("File transfer completed successfully.")
        else:
            print("File transfer failed.")
    elif mode == "3":
        use_password = input("Is the incoming file encrypted? (y/n): ").strip().lower()
        password = None
        if use_password == "y":
            password = getpass.getpass("Enter password for decryption: ")
        start_listening_mode(password)
    else:
        print("Invalid mode selected.")

if __name__ == "__main__":
    main()
