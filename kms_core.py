# kms_core.py
import os, json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import base64
import secrets

class KMS:
    def __init__(self, key_dir='keys'):
        os.makedirs(key_dir, exist_ok=True)
        self.key_dir = key_dir

    def generate_user_keys(self, user):
        priv_path = f"{self.key_dir}/{user}_private.pem"
        pub_path = f"{self.key_dir}/{user}_public.pem"
        if not os.path.exists(priv_path):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            with open(priv_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(pub_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

        self.get_or_generate_aes_key(user)
        self.get_or_generate_fernet_key(user)

    def load_private_key(self, user):
        with open(f"{self.key_dir}/{user}_private.pem", 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_public_key(self, user):
        with open(f"{self.key_dir}/{user}_public.pem", 'rb') as f:
            return serialization.load_pem_public_key(f.read())

    def get_or_generate_aes_key(self, user):
        path = f"{self.key_dir}/{user}_aes.key"
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        key = secrets.token_bytes(32)
        with open(path, "wb") as f:
            f.write(key)
        return key

    def get_or_generate_fernet_key(self, user):
        path = f"{self.key_dir}/{user}_fernet.key"
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(key)
        return key

    def encrypt_for_user(self, recipient, message, algorithm="RSA"):
        if algorithm == "RSA":
            pub = self.load_public_key(recipient)
            return pub.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).hex()

        elif algorithm == "AES":
            key = self.get_or_generate_aes_key(recipient)
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(message.encode()) + encryptor.finalize()
            return (iv + encrypted).hex()

        elif algorithm == "Fernet":
            key = self.get_or_generate_fernet_key(recipient)
            f = Fernet(key)
            return f.encrypt(message.encode()).decode()

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def decrypt_for_user(self, user, ciphertext, algorithm="RSA"):
        if algorithm == "RSA":
            priv = self.load_private_key(user)
            return priv.decrypt(
                bytes.fromhex(ciphertext),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()

        elif algorithm == "AES":
            key = self.get_or_generate_aes_key(user)
            ciphertext_bytes = bytes.fromhex(ciphertext)
            iv = ciphertext_bytes[:16]
            actual_ciphertext = ciphertext_bytes[16:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            return (decryptor.update(actual_ciphertext) + decryptor.finalize()).decode()

        elif algorithm == "Fernet":
            key = self.get_or_generate_fernet_key(user)
            f = Fernet(key)
            return f.decrypt(ciphertext.encode()).decode()

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
