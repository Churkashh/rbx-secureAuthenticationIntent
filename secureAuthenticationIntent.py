import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


SEPARATOR = "|"

def fetch_secureAuthenticationIntent(serverNonce: str): # v1/getServerNonce
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    clientPublicKey = base64.b64encode(public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode()
    
    clientEpochTimestamp = int(time.time())
    
    payload = SEPARATOR.join([clientPublicKey, str(clientEpochTimestamp), serverNonce])
    saiSignature = base64.b64encode(private_key.sign(
        str(payload).encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )).decode()
    
    return {
        'clientPublicKey': clientPublicKey,
        'clientEpochTimestamp': clientEpochTimestamp,
        'serverNonce': serverNonce,
        'saiSignature': saiSignature,
    }
