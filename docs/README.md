# Cryptographic Algorithms

This project implements custom cryptographic algorithms in Python, specifically **SHA-256** and **SHA-512**. It includes PyTest to verify the correctness of 
the implementations by comparing them with Python's built-in `hashlib` library.

## Overview
Cryptographic hashing functions like SHA-256 and SHA-512 are fundamental to various fields, including data integrity, digital signatures, and password hashing.
This project explores these algorithms by creating custom implementations.

### SHA-256

The following components make up the SHA-256 implementation in this project:

- **SHA-256 Constants**: A list of predefined constants, derived from the fractional parts of the cube roots of the first 64 prime numbers.
- **Right Rotate Function (`right_rotate`)**: A helper function for circular bitwise shifts, which is used extensively in the compression process.
- **Compression Function (`sha256_compress`)**: This function processes each 512-bit chunk of the message and updates the hash values according to the SHA-256 algorithm.
- **Padding Function (`sha256_pad`)**: Ensures that the input message is padded correctly to a multiple of 512 bits, as required by the SHA-256 algorithm.
- **Main Hash Function (`sha256`)**: The core function that computes the SHA-256 hash of a given message, using the compression function iteratively on each message chunk.

### SHA-512

The SHA-512 implementation follows a structure similar to the SHA-256 implementation, with some key differences:
- **SHA-512 Constants**: A list of predefined constants, derived from the first 80 prime numbers, used for 64-bit word operations.
- **Right Rotate Function (`right_rotate`)**: As in SHA-256, a helper function for bitwise shifts but adapted for 64-bit words.
- **Compression Function (`sha512_compress`)**: This function processes each 1024-bit chunk of the message and updates the hash values according to the SHA-512 algorithm.
- **Padding Function (`sha512_pad`)**: Pads the input message to a multiple of 1024 bits as required by the SHA-512 algorithm.
- **Main Hash Function (`sha512`)**: The core function that computes the SHA-512 hash of a given message.

## Examples

To use the custom implementations, simply import the relevant functions from the `sha256.py` or `sha512.py` files. Below are examples for both:

### SHA-256

```python
def example1():
    message = b"Hello World!"
    print(f"Example 1: Hello World! = {sha256(message)}")
```
```bash
Example 1: Hello World! = 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
```

### SHA-512

```python
def example1():
    message = b"Hello World!"
    print(f"Example 1: Hello World! = {sha512(message)}")
```
```bash
Example 1: Hello World! = 861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8
```