from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

key = AESGCM.generate_key(bit_length=256)
print(base64.b64encode(key).decode())
