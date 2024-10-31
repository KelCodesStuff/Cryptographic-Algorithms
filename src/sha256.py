# sha256.py

import struct

# Constants for SHA-256 (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Right rotate function (circular shift right), a key operation in SHA-256
def right_rotate(value, n):
    return (value >> n) | (value << (32 - n)) & 0xffffffff

# SHA-256 compression function
# This function processes each 512-bit chunk and updates the hash values
def sha256_compress(chunk, h0, h1, h2, h3, h4, h5, h6, h7):
    # Prepare the message schedule array (w) with 64 entries
    # First 16 words are directly from the chunk, next 48 are calculated
    w = list(struct.unpack('>16L', chunk)) + [0] * 48

    # Extend the first 16 words into the remaining 48
    for i in range(16, 64):
        # σ0 and σ1 are defined by bitwise operations on previous words
        s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff

    # Initialize working variables with the current hash values
    a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

    # Perform the main SHA-256 compression loop (64 rounds)
    for i in range(64):
        # Compression operations involving bitwise logic, additions, and rotations
        s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ (~e & g) # Choice operation
        temp1 = (h + s1 + ch + K[i] + w[i]) & 0xffffffff
        s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c) # Majority operation
        temp2 = (s0 + maj) & 0xffffffff

        # Update the working variables
        h = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    # Add the compressed chunk's hash to the current hash value
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff
    h5 = (h5 + f) & 0xffffffff
    h6 = (h6 + g) & 0xffffffff
    h7 = (h7 + h) & 0xffffffff

    # Return updated hash values
    return h0, h1, h2, h3, h4, h5, h6, h7

# Padding function: Pads the input message so its length is a multiple of 512 bits
def sha256_pad(message):
    # Append the bit '1' (0x80 in hex) to the message
    length = struct.pack('>Q', len(message) * 8) # Length of original message in bits
    message += b'\x80'

    # Pad with '0' bytes until the message length is congruent to 448 mod 512
    message += b'\x00' * ((56 - len(message) % 64) % 64)

    # Append the original message length as a 64-bit big-endian integer
    message += length
    return message

# Main SHA-256 function: Takes in a message and returns its SHA-256 hash in hexadecimal format
def sha256(message):
    # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    h0, h1, h2, h3, h4, h5, h6, h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    )

    # Pad the message so that its length becomes a multiple of 512 bits
    message = sha256_pad(message)

    # Process the message in successive 512-bit (64-byte) chunks
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        # Update hash values after processing each chunk
        h0, h1, h2, h3, h4, h5, h6, h7 = sha256_compress(chunk, h0, h1, h2, h3, h4, h5, h6, h7)

    # Concatenate the final hash values to produce the final digest
    return ''.join(f'{x:08x}' for x in (h0, h1, h2, h3, h4, h5, h6, h7))

# Example usage functions to demonstrate the SHA-256 implementation with different inputs
def example1():
    message = b"Hello World!"
    print(f"Example 1: Hello World! = {sha256(message)}")

def example2():
    message = b"This is the SHA-256 Hashing Algorithm"
    print(f"Example 2: This is the SHA-256 Hashing Algorithm = {sha256(message)}")

def example3():
    message = b"My name is KelCodes and I wrote this program"
    print(f"Example 3: My name is KelCodes and I wrote this program = {sha256(message)}")

if __name__ == "__main__":
    example1()
    example2()
    example3()