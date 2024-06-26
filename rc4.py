import binascii

def KSA(key):
    """
    Key-Scheduling Algorithm (KSA) for RC4.

    Args:
    key (str): The secret key used for encryption.

    Returns:
    list: Permutation array (S) after key scheduling.
    """
    n = len(key)
    j = 0
    T = [key[i % n] for i in range(256)]
    S = list(range(256))
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap S[i] with S[j]
    return S

def PRGA(S):
    """
    Pseudo-Random Generation Algorithm (PRGA) for RC4.

    Args:
    S (list): Permutation array after key scheduling.

    Yields:
    int: Pseudo-random byte generated from PRGA.
    """
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap S[i] with S[j]
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key, plaintext):
    """
    RC4 encryption algorithm.

    Args:
    key (str): The secret key used for encryption.
    plaintext (str): The plaintext to be encrypted.

    Returns:
    str: The ciphertext generated by RC4 encryption.
    """
    key = [ord(c) for c in key]  # Convert key to list of integers
    S = KSA(key)  # Perform key-scheduling to initialize S array
    keystream = PRGA(S)  # Initialize PRGA to generate keystream
    ciphertext = [chr(ord(c) ^ next(keystream)) for c in plaintext]  # Encrypt plaintext by XORing with keystream
    return ''.join(ciphertext)

def detect_same_keystream(ciphertext1, ciphertext2):
    """
    Detects if the same keystream was used to encrypt two ciphertexts.

    Args:
    ciphertext1 (str): The first ciphertext.
    ciphertext2 (str): The second ciphertext.

    Returns:
    bool: True if the same keystream was used, False otherwise.
    """
    min_length = min(len(ciphertext1), len(ciphertext2))  # Determine the minimum length of the ciphertexts
    trimmed_ciphertext1 = ciphertext1[:min_length]  # Trim the longer ciphertext to match the length of the shorter one
    trimmed_ciphertext2 = ciphertext2[:min_length]
    
    xor_result = bytes([ord(c1) ^ ord(c2) for c1, c2 in zip(trimmed_ciphertext1, trimmed_ciphertext2)])  # XOR the ciphertexts
    
    for byte in xor_result:  # Check if the MSB of each byte in the XOR result is 0
        if byte & 0x80 != 0:
            return False
    
    return True

# Example usage
key = "secretkey"
key1 = "secretkey1"
plaintext1 = "Hello, World!"
plaintext2 = "Goodbye, World!"
plaintext3 = "Hello, Universe!"

ciphertext1 = RC4(key, plaintext1)
ciphertext2 = RC4(key, plaintext2)
ciphertext3 = RC4(key1, plaintext3)

print("Plaintext 1:", plaintext1)
print("Plaintext 2:", plaintext2)
print("Plaintext 3:", plaintext3)

print()

print("Ciphertext 1:", binascii.hexlify(ciphertext1.encode()).decode())
print("Ciphertext 2:", binascii.hexlify(ciphertext2.encode()).decode())
print("Ciphertext 3:", binascii.hexlify(ciphertext3.encode()).decode())

print()

result = detect_same_keystream(ciphertext1, ciphertext2)
print("Same keystream used for plaintext1 and plaintext2:", result)

result = detect_same_keystream(ciphertext1, ciphertext3)
print("Same keystream used for plaintext1 and plaintext3:", result)
