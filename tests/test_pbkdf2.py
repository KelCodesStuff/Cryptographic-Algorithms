# test_pbkdf2.py

import pbkdf2
import binascii

from src.pbkdf2 import pbkdf2

def test_pbkdf2():
    password = 'mysecretpassword'
    salt = 'randomsalt'
    iterations = 100000
    dklen = 32

    derived_key = pbkdf2.pbkdf2(password, salt, iterations, dklen, 'sha256')

    # Convert the derived key to hex for readable output
    print("Derived Key:", binascii.hexlify(derived_key))

if __name__ == "__main__":
    test_pbkdf2()