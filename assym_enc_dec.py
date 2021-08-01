import random, sys, os
import Crypto
from Crypto.Util import number
import base64 #This module provides data encoding and decoding as specified in RFC 3548.
import os #The OS module in Python provides a way of using operating system dependent functionality.
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sym_key_gen
import SymmetricEncryption


# ASYMMETRIC ENCRYPTION OF KEY i.e. CIPHER KEY
def assym_key_enc():
    publicvalue = number.getRandomRange(2 ** (128 - 1), 2 ** (128))
    f = Fernet(SymmetricEncryption.key)

    KeyMsg = str(publicvalue).encode('utf-8')
    assym_key_enc.tokenMsg = f.encrypt(KeyMsg)

    #PRINTING CIPHER-TEXT
    print("\nPRINTING CIPHER-KEY::")
    print(assym_key_enc.tokenMsg)



    # DIFFIE HELLMAN KEY EXCHANGE ALGORITHM

    # Variables Used
    sharedPrime = 23  # p i.e. public key
    sharedBase = 5    # g i.e. public key

    aliceSecret = random.randint(1,101)  # Private Key Selected,a
    bobSecret = random.randint(1,101)  # Private Key Selected,b

    # Begin
    print("Publicly Shared Variables:")
    print("    Publicly Shared Prime: ", sharedPrime)
    print("    Publicly Shared Base:  ", sharedBase)

    # Alice Sends Bob A = g^a mod p
    A = (sharedBase ** aliceSecret) % sharedPrime
    print("\n  Alice Sends Over Public Chanel: ", A)

    # Bob Sends Alice B = g^b mod p
    B = (sharedBase ** bobSecret) % sharedPrime
    print("\n Bob Sends Over Public Chanel: ", B )

    print("\n------------\n")
    print("Privately Calculated Shared Secret:")
    # Alice Computes Shared Secret: s = B^a mod p
    assym_key_enc.aliceSharedSecret = (B ** aliceSecret) % sharedPrime
    print("    Alice Shared Secret: ", assym_key_enc.aliceSharedSecret)

    # Bob Computes Shared Secret: s = A^b mod p
    bobSharedSecret = (A ** bobSecret) % sharedPrime
    #print("    Bob Shared Secret: ", bobSharedSecret)

    # ENCRYPTION USING DIFFIE HELLMAN KEY EXCHANGE ALGORITHM

    #password = b"password"
    #Password is the master password from which a derived key is generated
    #password = SymmetricKeyGeneration.random_key
    password = str(assym_key_enc.aliceSharedSecret).encode('utf-8')

    #print("password=",password)

    salt = os.urandom(8)
    """(Password-Based Key Derivation Function 2) are key derivation functions with a sliding computational cost, 
    aimed to reduce the vulnerability of encrypted keys to brute force attacks. 
    """
    #PBKDF2 applies a pseudorandom function, such as hash-based message authentication code (HMAC)
    #kdf is the generated derived key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), #PRF=pseudo random function
        length=32,#length=32 is fixed . #desired bit-length of the derived key
        salt=salt, #salt is a sequence of bits, known as a cryptographic salt
        iterations=100000,#number of iterations desired
        backend=default_backend()
        )
    assym_key_enc.key = base64.urlsafe_b64encode(kdf.derive(password))

    #PRINTING SYMMETRIC KEY
    #print("\nPRINTING SYMMETRIC KEY::")
    #print(key)

    #with open("SymmetricKey.txt",'w') as file:
    #file.write(key)
    #file.close()
    f = Fernet(assym_key_enc.key)

    msg =  str(assym_key_enc.aliceSharedSecret).encode('utf-8')
    token = f.encrypt(msg)

    #PRINTING CIPHER-TEXT
    #print("\nPRINTING CIPHER-TEXT::")
    #print(token)


# DECRYPTION USING DIFFIE HELLMAN KEY EXCHANGE ALGORITHM
def assym_key_dec(event=None):
    f = Fernet(assym_key_enc.key)
    msg = str(assym_key_enc.aliceSharedSecret).encode('utf-8')
    token = f.encrypt(msg)
    result=f.decrypt(token)

    #PRINTING DECRYPTED TEXT
    print("\nPRINTING DECRYPTED KEY::")
    print(result)

    # ASYMMETRIC DECRYPTION OF CIPHER KEY

    resultMsg=assym_key_enc.tokenMsg.decode('utf-8')
    #PRINTING DECRYPTED TEXT
    print("\nPRINTING DECRYPTED ASYMMETRIC KEY::")
    print(resultMsg)
print(assym_key_enc())
print(assym_key_dec())