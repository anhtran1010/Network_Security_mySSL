import socket
import os
import sys

from cryptography import x509
import time
from key_generate import derived_keys
import base64
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

#Generating client nonce. The nonce is 32 octets, with the first 4 bytes being the Unix time
now_ms = int(time.time())
now_ms = now_ms.to_bytes(4, 'big')
client_nonce = now_ms + os.urandom(28)
cert_file = sys.argv[1]

HOST_SERVER = "127.0.0.1"  # The server's hostname or IP address
PORT_SERVER = 65432  # The port used by the server
server_cert_file = open(r"server/server_certificate.pem").read().encode()
server_cert = x509.load_pem_x509_certificate(server_cert_file)
server_public_key = server_cert.public_key()

client_cert_file = open(cert_file).read().encode()
client_cert = x509.load_pem_x509_certificate(client_cert_file)
client_cert_bytes= client_cert.public_bytes(Encoding.PEM)
client_private_key_file = open(r"client/key.pem").read().encode()
client_private_key = load_pem_private_key(client_private_key_file, b"passphrase")

Client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

Client_socket.connect((HOST_SERVER, PORT_SERVER))
print("="*10 + "client chosen data encryption, integrity protection algorithms, certificate, and encrypted nonce"+"="*10)
client_nonce_encrypt = server_public_key.encrypt(
    client_nonce,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
authenticate_message_to_server = b"Fernet,,,ChaCha20Poly1305,,," + client_cert_bytes + b",,," +client_nonce_encrypt
print("Message to send to server: ", authenticate_message_to_server)
Client_socket.sendall(authenticate_message_to_server)

print("="*10 + "client received server certificate and perform authentication"+"="*10)
server_cert_message = Client_socket.recv(4096)
server_cert_list = server_cert_message.split(b",,,")
print("Authenticate message from server: ", server_cert_message)
Server_nonce_encrypt = server_cert_list[1]
Server_cert = server_cert_list[0]
try:
    Server_cert = x509.load_pem_x509_certificate(Server_cert)
    server_public_key.verify(
        Server_cert.signature,
        Server_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        Server_cert.signature_hash_algorithm
    )
except InvalidSignature:
    print("Fail to authenticate server")
    exit()

#decrypt server nonce
server_nonce = client_private_key.decrypt(
                Server_nonce_encrypt,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
int_client_nonce = int.from_bytes(client_nonce, 'big')
int_server_nonce = int.from_bytes(server_nonce, 'big')
master_key = int_client_nonce^int_server_nonce
master_key = master_key.to_bytes(32, 'big')
print("Master Secret: ", master_key)

#generate the four key from master secret
encryption_client_k, encryption_server_k, integrity_client_k, integrity_server_k = derived_keys(master_key)

print("="*10 + "sending server the master secret encrypted with server's public key"+"="*10)
master_secret_msg = server_public_key.encrypt(
    master_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
Client_socket.sendall(master_secret_msg)

print("="*10 + "Client authenticate MAC message from server"+"="*10)
server_MAC = Client_socket.recv(4096)
digest_server_MAC = hashes.Hash(hashes.SHA1())
digest_server_MAC.update(authenticate_message_to_server+server_cert_message+master_secret_msg+b"SERVER")
server_MAC_authenticate = digest_server_MAC.finalize()

if server_MAC == server_MAC_authenticate:
    print("Server authenticate successfully")
else:
    print("Fail to authenticate server")
    exit()

print("="*10 + "Client MAC message to server"+"="*10)
digest_client_MAC = hashes.Hash(hashes.SHA1())
digest_client_MAC.update(authenticate_message_to_server+server_cert_message+master_secret_msg+b"CLIENT")
client_MAC = digest_client_MAC.finalize()
Client_socket.sendall(client_MAC)

print("="*10 + "file send from server"+"="*10)
file_encrypted = b''  # recv() does return bytes
while True:
    try:
        chunk = Client_socket.recv(4096)  # some 2^n number
        if not chunk:  # chunk == ''
            break

        file_encrypted += chunk
    except socket.error:
        Client_socket.close()
        break
file_decryption_algo = Fernet(encryption_server_k)
file = file_decryption_algo.decrypt(file_encrypted)
f = open("client_file.dat", "wb")
f.write(file)
f.close()
print("file received complete")

