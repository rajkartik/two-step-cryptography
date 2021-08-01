import base64 #This module provides data encoding and decoding as specified in RFC 3548.
import os #The OS module in Python provides a way of using operating system dependent functionality.
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sym_key_gen

#password = b"password"
#Password is the master password from which a derived key is generated
password = sym_key_gen.random_key
salt = os.urandom(8)
"""(Password-Based Key Derivation Function 2) are key derivation functions with a sliding computational cost, 
aimed to reduce the vulnerability of encrypted keys to brute force attacks. 
"""
#PBKDF2 applies a pseudorandom function, such as hash-based message authentication code (HMAC)
#kdf is the generated derived key

"""
algorithm – An instance of HashAlgorithm.
length (int) – The desired length of the derived key in bytes. Maximum is (232 - 1) * algorithm.digest_size.
salt (bytes) – A salt. Secure values [1] are 128-bits (16 bytes) or longer and randomly generated.
iterations (int) – The number of iterations to perform of the hash function. This can be used to control the length of time the operation takes. Higher numbers help mitigate brute force attacks against derived keys. See OWASP’s Password Storage Cheat Sheet for more detailed recommendations if you intend to use this for password storage.
backend – An instance of PBKDF2HMACBackend.
"""

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(), #PRF=pseudo random function
    length=32,#length=32 is fixed . #desired bit-length of the derived key
    salt=salt, #salt is a sequence of bits, known as a cryptographic salt
    iterations=100000,#number of iterations desired
    backend=default_backend()
 )
key = base64.urlsafe_b64encode(kdf.derive(password))

#PRINTING SYMMETRIC KEY
#print("\nPRINTING SYMMETRIC KEY::")
#print(key)

#with open("SymmetricKey.txt",'w') as file:
#file.write(key)
#file.close()
f = Fernet(key)
'''
fileObj = open(demo_app.tail,'r')
content = fileObj.read()
msg = bytes(content, 'utf-8')
fileObj.close()

token = f.encrypt(msg)
'''
#print("ENCRYPTED DATA-----------")
#print(token)
#b'...'
#result=f.decrypt(token)

#print("DECRYPTED DATA-----------")
#print(result)
#b'Secret message!'