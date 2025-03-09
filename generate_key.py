from cryptography.fernet import Fernet

key = Fernet.generate_key()
print(f"Generated key: {key.decode()}")  # Save this key securely

# Save it to a file
with open("secret.key", "wb") as key_file:
    key_file.write(key)