# test_sha256.py

import hashlib
import pytest

from src.sha256 import sha256  # Assuming you have a custom sha256 function in sha256.py

# Test the custom SHA-256 implementation for the string "abc 123" and compare it with hashlib's SHA-256
def test_sha256():
    test_message = b"abc 123"

    # Calculate the hash using the custom SHA-256 implementation
    custom_sha256 = sha256(test_message)

    # Calculate the hash using Python's built-in hashlib for comparison
    hashlib_sha256 = hashlib.sha256(test_message).hexdigest()

    # Assert that both custom and hashlib's output are identical
    assert custom_sha256 == hashlib_sha256, "Hash does not match hashlib's SHA-256!"

# Test the custom SHA-256 implementation for an empty string and compare it with hashlib's SHA-256
def test_sha256_empty_string():
    test_message = b""

    # Calculate the hash using the custom SHA-256 implementation
    custom_sha256 = sha256(test_message)

    # Calculate the hash using Python's built-in hashlib for comparison
    hashlib_sha256 = hashlib.sha256(test_message).hexdigest()

    # Assert that both custom and hashlib's output are identical for the empty string
    assert custom_sha256 == hashlib_sha256, "Hash does not match hashlib's SHA-256 for an empty string!"

# Test the custom SHA-256 implementation for an empty string and compare it with hashlib's SHA-256
def test_sha256_long_message():
    test_message = b"a" * 1000000  # 1 million 'a' characters

    # Calculate the hash using the custom SHA-256 implementation
    custom_sha256 = sha256(test_message)

    # Calculate the hash using Python's built-in hashlib for comparison
    hashlib_sha256 = hashlib.sha256(test_message).hexdigest()

    # Assert that both custom and hashlib's output are identical for the long message
    assert custom_sha256 == hashlib_sha256, "Hash does not match hashlib's SHA-256 for a long message!"