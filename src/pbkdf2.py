# pbkdf2.py

import hashlib
import hmac

def pbkdf2(password, salt, iterations, dklen=None, hash_name="sha256"):
    # Convert password to bytes if necessary
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')

    hash_func = getattr(hashlib, hash_name)
    hlen = hash_func().digest_size
    dklen = dklen or hlen  # Derived key length defaults to hash output size if not provided

    # Number of blocks needed to generate the desired key length
    l = (dklen + hlen - 1) // hlen
    r = dklen - (l - 1) * hlen

    def prf(data):
        return hmac.new(password, data, hash_func).digest()

    # Main PBKDF2 loop
    derived_key = b""
    for i in range(1, l + 1):
        t = u = prf(salt + i.to_bytes(4, 'big'))
        for _ in range(iterations - 1):
            u = prf(u)
            t = bytes(x ^ y for x, y in zip(t, u))
        derived_key += t if i < l else t[:r]

    return derived_key

# Usage example:
password = "mypassword"
salt = "mysalt"
iterations = 100000
dklen = 32  # Desired key length in bytes

derived_key = pbkdf2(password, salt, iterations, dklen)
print(derived_key.hex())  # Print the derived key in hex format
