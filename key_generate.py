from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derived_keys(master_secret):
    encryption_salt_client = b'r\xad\xa1\x1b\x18\x90\xf1\xc0\xd42\x96}O|\xaa\xe4\xa2\x95\xa9`q6\xd7\xa0t\x7f\xd7\xb2T\x96\xdfM'
    encryption_salt_server = b'\xdf,q\xb7\xad\ti\x9a)U\x94\x80\x8d5\xc0/\xf1\x80[\xb9\x1f)\x15s2\x0f\x1a\x98#\xe3W\xfd'
    integrity_salt_client = b'\x19vr\x86I}\xdf\x88\x85\xd6\xdfv\xb4\xb4\x0f\xa1\xa3!\xb4!\x07M\xfeH\xf6o\xb2RsK\xd1\x9d'
    integrity_salt_server = b'\xe9\xe7\xbf\xcb\xea/vq\xee-(\x02\x06\xd4MH\xab\xfc\xa7`\x0ez\xe8\xca\x87\xaa\xea\xdc~A\x0cw'

    kdf_1 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=encryption_salt_client,
        iterations=390000,
    )
    key_1 = kdf_1.derive(master_secret)
    kdf_2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=encryption_salt_server,
        iterations=390000,
    )
    key_2 = kdf_2.derive(master_secret)
    kdf_3 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=integrity_salt_client,
        iterations=390000,
    )
    key_3 = kdf_3.derive(master_secret)
    kdf_4 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=integrity_salt_server,
        iterations=390000,
    )
    key_4 = kdf_4.derive(master_secret)
    return base64.urlsafe_b64encode(key_1), \
           base64.urlsafe_b64encode(key_2), \
           base64.urlsafe_b64encode(key_3), \
           base64.urlsafe_b64encode(key_4)
