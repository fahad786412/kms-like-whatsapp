# test_client.py
import requests

BASE_URL = "http://127.0.0.1:5000"

# Step 1: Register users
print("Registering users...")
requests.post(f"{BASE_URL}/register", json={"user": "fahad"})
requests.post(f"{BASE_URL}/register", json={"user": "ali"})

# Step 2: Encrypt a message
print("\nEncrypting message from fahad to ali (Fernet)...")
encrypt_response = requests.post(f"{BASE_URL}/encrypt", json={
    "sender": "fahad",
    "recipient": "ali",
    "message": "hello ali from fahad",
    "algorithm": "Fernet"
})
print("Encrypted:", encrypt_response.json())

# Step 3: Decrypt the message
encrypted_text = encrypt_response.json().get("encrypted")
print("\nDecrypting for ali...")
decrypt_response = requests.post(f"{BASE_URL}/decrypt", json={
    "user": "ali",
    "encrypted": encrypted_text,
    "algorithm": "Fernet"
})
print("Decrypted:", decrypt_response.json())

# Step 4: Fetch inbox for ali
print("\nFetching inbox for ali...")
inbox_response = requests.get(f"{BASE_URL}/inbox/ali")
print("Inbox:", inbox_response.json())
