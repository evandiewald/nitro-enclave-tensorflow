# crypto_utils.py

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import rsa as rsa_base
from PIL import Image


def generate_keys_rsa_base(save=False):
    (pubkey, privkey) = rsa_base.newkeys(512)
    if save:
        with open('parent_public_key.pem', 'wb') as f:
            f.write(pubkey._save_pkcs1_pem())
        with open('parent_private_key.pem', 'wb') as f:
            f.write(privkey._save_pkcs1_pem())
    return (pubkey, privkey)


def load_rsa_keys():
    with open('my_public_key.pem', 'rb') as f:
        pubkey = rsa_base.PublicKey.load_pkcs1(f.read())
    with open('my_private_key.pem', 'rb') as f:
        privkey = rsa_base.PrivateKey.load_pkcs1(f.read())
    return (pubkey, privkey)


def generate_and_save_keys(private_key_path='private_key.pem', public_key_path='public_key.pem'):
    # generate and store keys
    # private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(private_key_path, 'wb') as f:
        f.write(pem)

    # public key
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(public_key_path, 'wb') as f:
        f.write(pem)

    return pem


def generate_keys_in_memory():
    # keeps keys in memory
    # private key
    print('Generating private key.')
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    print('Serializing private key.')
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print('Generating public key.')
    # public key
    public_key = private_key.public_key()
    print('Serializing public key.')
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes


def get_public_key(public_key_path: str, get_bytes=True):
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if get_bytes:
        return public_key_bytes
    else:
        return public_key


def get_private_key(private_key_path: str):
    with open(private_key_path, 'rb') as key_file:
        private_key = rsa_base.PrivateKey.load_pkcs1(key_file.read())
    return private_key

def encrypt(file_path, public_key_path):
    public_key = get_public_key(public_key_path, get_bytes=False)
    symmetric_key = Fernet.generate_key()
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(file_path, 'rb') as file_in:
        encrypted_contents = Fernet(symmetric_key).encrypt(file_in.read())
    with open(file_path+'.encrypted', 'wb') as file_out:
        file_out.write(encrypted_contents)
    return encrypted_key


def encrypt_image(file_path, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = rsa_base.PublicKey.load_pkcs1(f.read())
    symmetric_key = Fernet.generate_key()
    encrypted_key = rsa_base.encrypt(symmetric_key, public_key)
    encrypted_contents = Fernet(symmetric_key).encrypt(Image.open(file_path).tobytes())
    with open(file_path+'.encrypted', 'wb') as file_out:
        file_out.write(encrypted_contents)
    return encrypted_key


def encrypt_in_memory(incoming_bytes: bytes, public_key):
    symmetric_key = Fernet.generate_key()
    encrypted_key = rsa_base.encrypt(symmetric_key, public_key)
    encrypted_contents = Fernet(symmetric_key).encrypt(incoming_bytes)
    return encrypted_key, encrypted_contents


def decrypt(file_path, encrypted_key, private_key_path):
    with open(private_key_path, 'rb') as key_file:
        private_key = rsa_base.PrivateKey.load_pkcs1(key_file.read())
    decrypted_key = rsa_base.decrypt(encrypted_key, private_key)
    with open(file_path, 'rb') as encrypted_file:
        decrypted_contents = Fernet(decrypted_key).decrypt(encrypted_file.read())
    return decrypted_contents


def decrypt_in_memory(encrypted_contents: bytes, encrypted_key: bytes, private_key):
    print('Decrypting symmetric key')
    decrypted_key = rsa_base.decrypt(encrypted_key, private_key)
    print('Decrypting contents with symmetric key')
    decrypted_contents = Fernet(decrypted_key).decrypt(encrypted_contents)
    return decrypted_contents