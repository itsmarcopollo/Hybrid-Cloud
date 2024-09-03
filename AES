import json
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random

def xor_data(data, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key * (len(data) // len(key) + 1)))

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    return cipher.encrypt(padded_data)

def aes_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    return unpad(decrypted_data, AES.block_size).decode('utf-8')

def maritime_search_and_rescue():
    return random.randint(1, 10)

def ant_colony_optimization(data):
    return data  
    
def preprocess_user_data(user):
    user = user.replace("'", '"')
    return user

def load_user_data(file_name):
    with open(file_name, 'r') as file:
        data = file.read().split("===========================================")
    return [json.loads(preprocess_user_data(user.strip())) for user in data if user.strip()]

def encrypt_user_data(user_data, aes_key, xor_key):
    encrypted_data = []
    for user in user_data:
        user_json = json.dumps(user)
        channel = maritime_search_and_rescue()
        optimized_data = ant_colony_optimization(user_json)
        xor_encrypted = xor_data(optimized_data, xor_key)
        aes_encrypted = aes_encrypt(xor_encrypted, aes_key)
        encrypted_data.append((channel, aes_encrypted))
    return encrypted_data

def decrypt_user_data(encrypted_data, aes_key, xor_key):
    decrypted_data = []
    for channel, encrypted in encrypted_data:
        aes_decrypted = aes_decrypt(encrypted, aes_key)
        xor_decrypted = xor_data(aes_decrypted, xor_key)
        optimized_data = xor_decrypted
        try:
            user_data = json.loads(optimized_data)
        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {e}")
            print(f"Optimized Data: {optimized_data}")
            raise
        decrypted_data.append(user_data)
    return decrypted_data

def save_to_file(data, file_path):
    with open(file_path, 'w') as file:
        file.write(data)

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

if __name__ == "__main__":
    directory = 'Cloud_Server'
    ensure_directory_exists(directory)
    aes_key = os.urandom(16)
    xor_key = "secret_key"
    user_data = load_user_data('Decrypted_Data_Verified.txt')
    encrypted_data = encrypt_user_data(user_data, aes_key, xor_key)
    encrypted_file_path = os.path.join(directory, 'Encrypted_Data.txt')
    encrypted_data_str = '\n'.join([f"Channel: {channel}, Encrypted: {encrypted.hex()}" for channel, encrypted in encrypted_data])
    save_to_file(encrypted_data_str, encrypted_file_path)    
    print("\n=================\nEncrypted Data:\n=================\n\n")
    time.sleep(3)
    print(encrypted_data_str)
    time.sleep(5)
    decrypted_data = decrypt_user_data(encrypted_data, aes_key, xor_key)
    decrypted_file_path = os.path.join(directory, 'Decrypted_Data.txt')
    decrypted_data_str = json.dumps(decrypted_data, indent=4)
    save_to_file(decrypted_data_str, decrypted_file_path)
    print("\n\n=================\nDecrypted Data:\n=================\n\n")
    time.sleep(3)
    print(decrypted_data_str)
