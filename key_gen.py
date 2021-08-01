import random, sys, os
import Crypto
from Crypto.Util import number
def inverseMod(a, m):
    m0 = m
    y = 0
    x = 1

    if (m == 1):
        return 0

    while (a > 1):
        # q is quotient
        q = a // m

        t = m

        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y

        # Update x and y
        y = x - q * y
        x = t

        # Make x positive
    if (x < 0):
        x = x + m0

    return x
def main():

   generateKey(128)



'''def inverseMod(a, m):
    for i in range(1,m):
        if (m*i + 1) % a == 0:
            return ( m*i + 1) // a
    return None
'''
def gcd(a, b):

    while b:
        a, b = b, a%b
    return a
def generateKey(keySize):
    # Creates a public/private key pair with keys that are keySize bits in
    # size. This function may take a while to run.
    # Step 1: Create two prime numbers, p and q. Calculate n = p * q.
    print('Generating p prime...')

    p = number.getPrime(keySize, os.urandom)
    print('Generating q prime...')
    q=number.getPrime(keySize,os.urandom)
    n = p * q

 # Step 2: Create a number e that is relatively prime to (p-1)*(q-1).
    print('Generating e that is relatively prime to (p-1)*(q-1)...')
    while True:
      # Keep trying random numbers for e until one is valid.
        e = number.getRandomRange(2 ** (keySize - 1), 2 ** (keySize))

        if gcd(e, (p - 1) * (q - 1)) == 1:
           break


    # Step 3: Calculate d, the mod inverse of e.
   # print((p-1) * (q-1))
   # print(e)
    print('Calculating d that is mod inverse of e...')
    d = inverseMod(e, (p - 1) * (q - 1))

    publicKey = (n, e)
    privateKey = (n, d)
    print('Public key:', publicKey)
    print('Private key:', privateKey)
    return publicKey, privateKey





 # the main() function.
if __name__ == '__main__':
     main()