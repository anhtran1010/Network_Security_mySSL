import socket
import os
import sys

from cryptography import x509
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from key_generate import derived_keys

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

#Generating server nonce. The nonce is 32 octets, with the first 4 bytes being the Unix time
now_ms = int(time.time())
now_ms = now_ms.to_bytes(4, 'big')
server_nonce = now_ms + os.urandom(28)

cert_file = sys.argv[1]
server_cert_file = open(cert_file).read().encode()
server_cert = x509.load_pem_x509_certificate(server_cert_file)
server_cert_bytes= server_cert.public_bytes(Encoding.PEM)

client_cert_file = open(r"client/client_certificate.pem").read().encode()
client_cert = x509.load_pem_x509_certificate(client_cert_file)
client_public_key = client_cert.public_key()

server_private_key_file = open(r"server/key.pem").read().encode()
server_private_key = load_pem_private_key(server_private_key_file, b"passphrase")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    s.settimeout(10)
    with conn:
        print("Connected by", addr)
        while True:

            client_cert_message = conn.recv(4096)
            client_cert_list = client_cert_message.split(b",,,")
            if not client_cert_message:
                break
            print(
                "=" * 10 + "message from client: data encryption, integrity protection algorithms, certificate, and encrypted nonce" + "=" * 10)
            client_nonce_encrypt = client_cert_list[-1]
            other_info = client_cert_message[:-160] #this include the algorithms used and the client cert
            encryption_algo = client_cert_list[0]
            integrity_algo = client_cert_list[1]
            Client_cert = x509.load_pem_x509_certificate(client_cert_list[2])
            try:
                client_public_key.verify(
                    Client_cert.signature,
                    Client_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    Client_cert.signature_hash_algorithm
                )
            except InvalidSignature:
                print("Fail to authenticate client")
                exit()
            client_nonce = server_private_key.decrypt(
                client_nonce_encrypt,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            int_client_nonce = int.from_bytes(client_nonce, 'big')
            int_server_nonce = int.from_bytes(server_nonce, 'big')
            master_key = int_client_nonce ^ int_server_nonce
            master_key = master_key.to_bytes(32, 'big')
            print("Master Secret: ", master_key)
            # generate the four key from master secret
            encryption_client_k, encryption_server_k, integrity_client_k, integrity_server_k = derived_keys(master_key)

            print("=" * 10 + "send server's nonce and certificate to client" + "=" * 10)
            #encrypting server nonce
            server_nonce_encrypt = client_public_key.encrypt(
                server_nonce,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            server_cert_message = server_cert_bytes+b",,,"+server_nonce_encrypt
            print("Server certication message: ", server_cert_message)
            conn.sendall(server_cert_message)

            print("=" * 10 + "client encrypted master secret" + "=" * 10)
            master_secret_msg = conn.recv(4096)
            master_secret_decrypt = server_private_key.decrypt(
                master_secret_msg,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            if master_secret_decrypt == master_key:
                print("Master Secret Confirm")
            else:
                print(master_secret_decrypt)
                print(master_key)
                print("This is not the correct client, failed authentication")
                exit()

            print("=" * 10 + "server MAC message to client" + "=" * 10)
            digest_server_MAC = hashes.Hash(hashes.SHA1())
            digest_server_MAC.update(client_cert_message + server_cert_message + master_secret_msg + b"SERVER")
            server_MAC = digest_server_MAC.finalize()
            conn.sendall(server_MAC)

            print("=" * 10 + "client MAC message to authenticate" + "=" * 10)
            digest_client_MAC = hashes.Hash(hashes.SHA1())
            digest_client_MAC.update(
                client_cert_message + server_cert_message + master_secret_msg + b"CLIENT")
            client_MAC_authenticate = digest_client_MAC.finalize()
            client_MAC_message = conn.recv(4096)
            if client_MAC_message ==  client_MAC_authenticate:
                print("Authenticate client successfully")
            else:
                print("Failed Authentication")
                exit()

            print("=" * 10 + "send big file to client" + "=" * 10)

            file = open(r"random_big_file.dat", 'rb')
            sendfile = file.read(9000000)
            file_encryption_algo = Fernet(encryption_server_k)
            sendfile_encrypted = file_encryption_algo.encrypt(sendfile)
            conn.sendall(sendfile)
            print("File send complete")

