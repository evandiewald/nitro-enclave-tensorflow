# vsock-parent.py
# usage ex: python3 vsock-parent.py server 5005
# (in a new terminal): python3 vsock-parent.py client 16 5006 (16 is the enclave CID)

import argparse
import socket
from struct import unpack, pack
import sys
from crypto_utils import *
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class VsockStream:
    """Client"""
    def __init__(self, conn_tmo=15):
        self.conn_tmo = conn_tmo
        self.parent_private_key = None
        self.parent_public_key = None
        self.enclave_private_key = None
        

    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)

    def send_data(self, data):
        """Send data to the remote endpoint"""
        self.sock.sendall(data)
        self.sock.close()

    def send_keys_parent(self):
        print('Loading keys.')
        (self.parent_public_key, self.parent_private_key) = load_rsa_keys()
        length = pack('>Q', len(self.parent_public_key._save_pkcs1_pem()))
        self.sock.sendall(length)
        self.sock.sendall(self.parent_public_key._save_pkcs1_pem())
        print('Keys sent from parent')

    def send_image_parent(self, endpoint):
        encrypted_key = encrypt_image('basal_cell_carcinoma_example.png', 'enclave_public_key_received.pem')
        with open('basal_cell_carcinoma_example.png.encrypted', 'rb') as f:
            image_contents = f.read()

        length = pack('>Q', len(image_contents))
        print(f'Sending image of length {str(len(image_contents))}')
        while True:
            try:
                self.sock.sendall(length)
                print('Length message sent')
                self.sock.sendall(image_contents)
                break
            except socket.timeout:
                time.sleep(2)
    
        length = pack('>Q', len(encrypted_key))
        print('Sending symmetric key of length: ', str(len(encrypted_key)))
        self.connect(endpoint)
        self.sock.sendall(length)
        self.sock.sendall(encrypted_key)

        self.sock.close()
            

def client_handler(args):

    client = VsockStream()
    endpoint = (args.cid, args.port)
    client.connect(endpoint)

    client.send_keys_parent()
    
    client.connect(endpoint)
    client.send_image_parent(endpoint)


class VsockListener:
    """Server"""
    def __init__(self, conn_backlog=128):
        self.conn_backlog = conn_backlog
        self.files_received = [0, 0, 0] # --> [sym key, inference, pub key]

    def bind(self, port):
        """Bind and listen for connections on the specified port"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)

    def recv_data(self):
        """Receive data from a remote endpoint"""
        while True:
            (from_client, (remote_cid, remote_port)) = self.sock.accept()
            data = from_client.recv(1024).decode()
            if not data:
                break
            print(data)
            from_client.close()

    def recv_data_parent(self):
        full_msg = ''
        while sum(self.files_received) < 3:
            (from_client, (remote_cid, remote_port)) = self.sock.accept()
            msg = from_client.recv(8)
            if len(msg) == 8:
                (length,) = unpack('>Q', msg)
                data = b''
                while len(data) < length:
                    to_read = length - len(data)
                    data += from_client.recv(1024 if to_read > 1024 else to_read)
                
                if length > 120 and length < 257: # this must be our encrypted symmetric key (usually 256 bytes)
                    with open('inference_key_received', 'wb') as f:
                        f.write(data)
                    print('Encryption key received.')
                    self.files_received[0] = 1
                    if self.files_received[0] and self.files_received[1]:
                        break
                elif length < 120: # assume anything smaller is our (encrypted) inference
                    with open('inference_received.txt.encrypted', 'wb') as f:
                        f.write(data)
                    print('Encrypted inference received.')
                    self.files_received[1] = 1
                    if self.files_received[0] and self.files_received[1]:
                        break
                else: # enclave's public key    
                    with open('enclave_public_key_received.pem', 'wb') as f:
                        f.write(data)
                    print('Enclave\'s public key received.')
                    self.files_received[2] = 1

        print('All files received, shutting down...')
        from_client.close()

        # in reality, this decryption would actually happen on the client's machine
        print('Attempting to decrypt inference...')
        with open('inference_key_received', 'rb') as f:
            encrypted_key = f.read()
        decrypted_contents = decrypt('inference_received.txt.encrypted', encrypted_key, 'my_private_key.pem')
        with open('inference_received_decrypted.txt', 'wb') as f:
            f.write(decrypted_contents)

        print('Decryption successful!')
        LABELS = [
            'Actinic Keratoses and Intraepithelial Carcinoma',
            'Basal Cell Carcinoma',
            'Benign Keratosis',
            'Dermatofibroma',
            'Melanoma',
            'Melanocytic Nevi',
            'Vascular Lesions'
        ]
        print('Classification received: ', LABELS[int.from_bytes(decrypted_contents, 'big')])


def server_handler(args):
    print('Server ready!')
    server = VsockListener()
    server.bind(args.port)
    # server.recv_data()
    server.recv_data_parent()


def main():
    parser = argparse.ArgumentParser(prog='vsock-sample')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    client_parser = subparsers.add_parser("client", description="Client",
                                          help="Connect to a given cid and port.")
    client_parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument("port", type=int, help="The remote endpoint port.")
    client_parser.set_defaults(func=client_handler)

    server_parser = subparsers.add_parser("server", description="Server",
                                          help="Listen on a given port.")
    server_parser.add_argument("port", type=int, help="The local port to listen on.")
    server_parser.set_defaults(func=server_handler)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()