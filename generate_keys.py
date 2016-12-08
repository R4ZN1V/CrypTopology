from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

#this code targat is to generate the RSA private&public keys for the init message
#YOU MUST RUN THIS CODE BEFORE ACTIVATING THE SYSTEM

#create private key
private_key = rsa.generate_private_key(public_exponent=65537,key_size=4096,backend=default_backend())

#create format to private key
pem1 = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
pem1.splitlines()[0]

#create format to public key
public_key = private_key.public_key()
pem2 = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
pem2.splitlines()[0]

f1 = open('private_key', 'wb')
f1.write(pem1)
f2 = open('public_key', 'wb')
f2.write(pem2)

f1.close()
f2.close()
