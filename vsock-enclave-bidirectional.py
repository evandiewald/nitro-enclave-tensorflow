# vsock-enclave-bidirectional.py
# see Dockerfile for usage

import argparse
import socket
from struct import unpack, pack
import sys
from crypto_utils import *
from predict_tflite import classify_image_in_memory
import time
import random
import subprocess
import rsa as rsa_base

random.seed()

print('Hello from within the enclave!')


class VsockStream:
    """Client"""
    def __init__(self, conn_tmo=60, conn_backlog=128):
        self.conn_tmo = conn_tmo
        self.conn_backlog = conn_backlog
        self.image_received = None
        self.parent_public_key = None
        self.encrypted_image_received = None
        self.encrypted_key_received = None

        self.files_received = [0, 0, 0] # --> [image, sym key, pub key]
        self.all_files_received = False
    
        print('Loading enclave private/public keypair...')
        (self.enclave_public_key, self.enclave_private_key) = load_rsa_keys()
        print('done.')

    def bind(self, port):
        """Bind and listen for connections on the specified port"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)

    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)

    def send_keys_enclave(self):
        length = pack('>Q', len(self.enclave_public_key._save_pkcs1_pem()))
        self.sock.sendall(length)
        print('Sending public key of length: ', str(len(self.enclave_public_key._save_pkcs1_pem())))
        self.sock.sendall(self.enclave_public_key._save_pkcs1_pem())
        print('Keys sent from enclave')

    def classify_and_send_inference(self, endpoint):
        if self.image_received:
            print('Classifying image...')
            output = classify_image_in_memory(self.image_received)
            print('Generating some entropy...')
            subprocess.run('rngd -r /dev/urandom -o /dev/random', shell=True)
            print('Encrypting inference...')
            encrypted_key, encrypted_contents = encrypt_in_memory(output, self.parent_public_key)
            length = pack('>Q', len(encrypted_contents))
            print('Sending encrypted inference, length: ', str(len(encrypted_contents)))
            self.sock.sendall(length)
            self.sock.sendall(encrypted_contents)

            time.sleep(2)
            print('Sending encryption key...')
            length = pack('>Q', len(encrypted_key))
            self.connect(endpoint)
            self.sock.sendall(length)
            self.sock.sendall(encrypted_key)
            print('Length of encryption key: ', str(len(encrypted_key)))

            time.sleep(2)
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        else:
            print('Classification unsuccessful: image not received yet.')

    def recv_data_enclave(self):
        full_msg = ''
        
        (from_client, (remote_cid, remote_port)) = self.sock.accept()
        msg = from_client.recv(8)
        if len(msg) == 8:
            (length,) = unpack('>Q', msg)
            print(f'Message of length {str(length)} incoming.')
            data = b''
            while len(data) < length:
                to_read = length - len(data)
                data += from_client.recv(4096 if to_read > 4096 else to_read)
            if length > 500: # assume anything larger is our (encrypted) image
                self.encrypted_image_received = data
                print('Encrypted image received.')
                self.files_received[0] = 1
                if self.encrypted_key_received is not None and self.image_received is None:
                    print('Generating some entropy...')
                    subprocess.run('rngd -r /dev/urandom -o /dev/random', shell=True)
                    time.sleep(10)
                    self.image_received = decrypt_in_memory(self.encrypted_image_received, self.encrypted_key_received, self.enclave_private_key)
                    print('Image decrypted')
                else:
                    print('Still waiting for key to decrypt image...')
            elif length < 275: # this must be our encrypted symmetric key
                self.encrypted_key_received = data
                print('Encryption key received.')
                self.files_received[1] = 1
                if self.encrypted_image_received is not None and self.image_received is None:
                    print('Generating some entropy...')
                    subprocess.run('rngd -r /dev/urandom -o /dev/random', shell=True)
                    time.sleep(10)
                    self.image_received = decrypt_in_memory(self.encrypted_image_received, self.encrypted_key_received, self.enclave_private_key)
                    print('Image decrypted')
                else:
                    print('Have the key but still waiting for image to decrypt')
            else: # parent's public key
                self.parent_public_key = rsa_base.PublicKey.load_pkcs1(data)
                print('Parent\'s public key received.')
                self.files_received[2] = 1
        if sum(self.files_received) == 3:
            self.all_files_received = True
            print('All files received!')


def stream_handler(args):
    print('Enclave Client starting.')
    client = VsockStream()
    endpoint = (args.cid, args.port_out)
    client.connect(endpoint)

    # send public key to parent
    print('Enclave sending keys...')
    client.send_keys_enclave()

    time.sleep(2)

    # receive encrypted image, symmetric key, and public key
    client.bind(args.port_in)
    print('Ready to receive keys and files')
    while client.all_files_received == False:
        client.recv_data_enclave()
        time.sleep(2)

    # send inference back
    print('Enclave sending inference...')
    client.connect(endpoint)
    client.classify_and_send_inference(endpoint)


def main():
    parser = argparse.ArgumentParser(prog='vsock-enclave-bidirectional')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')

    parser.add_argument("cid", type=int, help="The parent instance CID (should be 3).")
    parser.add_argument("port_in", type=int, help="The port for traffic INTO enclave.")
    parser.add_argument("port_out", type=int, help="The port for traffic OUT OF enclave.")
    parser.set_defaults(func=stream_handler)


    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()