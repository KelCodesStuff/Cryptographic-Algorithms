# test_sha512.py

import hashlib

from src.sha512 import sha512  # Assuming you have a custom sha512 function in sha512.py

# Test the function against hashlib
def test_sha512():
    test_message = b"123 abc"
    custom_sha512 = sha512(test_message)
    hashlib_sha512 = hashlib.sha512(test_message).hexdigest()
    assert custom_sha512 == hashlib_sha512, "Hash does not match hashlib's SHA-512!"

def test_sha512_empty_string():
    test_message = b""
    custom_sha512 = sha512(test_message)
    hashlib_sha512 = hashlib.sha512(test_message).hexdigest()
    assert custom_sha512 == hashlib_sha512, "Hash does not match hashlib's SHA-512 for an empty string!"

def test_sha512_long_message():
    test_message = b"a" * 1000000  # 1 million 'a' characters
    custom_sha512 = sha512(test_message)
    hashlib_sha512 = hashlib.sha512(test_message).hexdigest()
    assert custom_sha512 == hashlib_sha512, "Hash does not match hashlib's SHA-512 for a long message!"