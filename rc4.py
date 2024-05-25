def KSA(key):
    n = len(key)
    j = 0
    T = [key[i % n] for i in range(256)]
    S = list(range(256))
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i] 
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key, plaintext):
    key = [ord(c) for c in key]
    S = KSA(key)
    keystream = PRGA(S)
    ciphertext = [chr(ord(c) ^ next(keystream)) for c in plaintext]
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
    min_length = min(len(ciphertext1), len(ciphertext2))
    trimmed_ciphertext1 = ciphertext1[:min_length]
    trimmed_ciphertext2 = ciphertext2[:min_length]
    
    xor_result = bytes([ord(c1) ^ ord(c2) for c1, c2 in zip(trimmed_ciphertext1, trimmed_ciphertext2)])
    
    for byte in xor_result:
        if byte & 0x80 != 0:
            return False
    
    return True


key = "secretkey"
plaintext1 = "Hello, World!"
plaintext2 = "Goodbye, World!"

ciphertext1 = RC4(key, plaintext1)
ciphertext2 = RC4(key, plaintext2)

result = detect_same_keystream(ciphertext1, ciphertext2)
print("Same keystream used:", result)
