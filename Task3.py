# rsa_textbook_demo.py
from Crypto.Util.number import getPrime, getRandomRange
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256

e = 65537
BIT_LENGTH = 2046
IV = get_random_bytes(16)


# region Helper functions
#Extended Euclidean Algorthim to find modular inverse
def extended_gcd(a, b): 
    if a == 0:
        return (b, 0, 1)
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)

#Modular Inverse function
def modular_inverse(a, m): 
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

def int_to_bytes(i, min_len=0):
    if i == 0:
        b = b"\x00"
    else:
        b = i.to_bytes((i.bit_length() + 7) // 8, "big")
    if min_len and len(b) < min_len:
        b = b"\x00" * (min_len - len(b)) + b
    return b

def bytes_to_int(b):
    return int.from_bytes(b, "big")

# RSA Functions
def generate_rsa(bits=1024):
    # bits for each prime; n will be ~2*bits
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)
    return {"n": n, "e": e, "d": d, "p": p, "q": q}

def rsa_encrypt_int(m_int, pub):
    n = pub["n"]; e = pub["e"]
    if not (0 <= m_int < n):
        raise ValueError("message integer must be in [0, n-1]")
    return pow(m_int, e, n)

def rsa_decrypt_int(c_int, priv):
    n = priv["n"]; d = priv["d"]
    return pow(c_int, d, n)

# helpers to encrypt/decrypt raw bytes (textbook RSA; no padding)
def rsa_encrypt_bytes(b_plain, pub):
    m_int = bytes_to_int(b_plain)
    return rsa_encrypt_int(m_int, pub)

def rsa_decrypt_bytes(c_int, priv, min_out_len=0):
    m_int = rsa_decrypt_int(c_int, priv)
    return int_to_bytes(m_int, min_len=min_out_len)
# endregion 

# region CBC Functions
def aes_cbc_encrypt(plaintext_bytes, key_32):
    # PKCS#7 padding
    pad_len = 16 - (len(plaintext_bytes) % 16)
    pt = plaintext_bytes + bytes([pad_len]) * pad_len
    cipher = AES.new(key_32, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pt)
    return ct

def aes_cbc_decrypt(ct, key_32):
    cipher = AES.new(key_32, AES.MODE_CBC, IV)
    pt = cipher.decrypt(ct)
    pad_len = pt[-1]
    if pad_len < 1 or pad_len > 16:
        print("Bad padding")
    return pt[:-pad_len]
# endregion 

def calcuate_sig_scheme(d1, d2, n):
    d3 = (d1 * d2) % n
    #d3 will have some m3 = m2 * m1 % n mathematically?
    #m3 will not be human readable nor editable nor intentional
    #but its enough to cause malicious integrity failing
    return d3 

# Verify textbook RSA signature: check sig^e mod n == m
def verify_signature(signature_int, message_int, pub):
    n, e = pub["n"], pub["e"]
    return pow(signature_int, e, n) == (message_int % n)

def main():
    keypair = generate_rsa(BIT_LENGTH)
    pub = {"n": keypair["n"], "e": keypair["e"]}
    priv = {"n": keypair["n"], "d": keypair["d"]}
    print("n bits:", keypair["n"].bit_length())

    # Alice chooses s (s in Z*_n) and publishes c = s^e mod n
    s = getRandomRange(2, pub["n"] - 1)
    c = rsa_encrypt_int(s, pub)
    print("\nAlice's secret s (kept secret by Alice):", s)
    print("Alice sends c = s^e mod n to Bob (int):", c)

    # Mallory intercepts the message (c) on the wire and replaces it
    # Simple attack: send c' = r^e so Alice will recover r (which Mallory knows)
    r = getRandomRange(2, pub["n"] - 1)   # Mallory's chosen value
    c_prime = rsa_encrypt_int(r, pub)       # r^e mod n
    print("\nMallory chooses an r (herself):", r)
    print("Mallory sends c' = r^e mod n instead of c.")

    # Alice (unaware) decrypts the received c' with her private key
    s_alice = rsa_decrypt_int(c_prime, priv)
    print("\nAlice decrypted c' and obtains s_alice:", s_alice)
    # s_alice should equal r
    assert s_alice == r

    # Alice derives symmetric key k = SHA256(s_alice) and encrypts a message
    k = sha256(int_to_bytes(s_alice)).digest()  # 32-byte key
    message = b"Hi Bob! This is a secret message from Alice."
    c0 = aes_cbc_encrypt(message, k)
    print("\nAlice sends AES-CBC ciphertext c0 (to Bob) encrypted with k = SHA256(s_alice).")

    # Mallory knows r => she knows SHA256(int_to_bytes(r)) and can decrypt c0
    k_mallory = sha256(int_to_bytes(r)).digest()
    recovered = aes_cbc_decrypt(c0, k_mallory)
    print("Mallory decrypts c0 and recovers:", recovered.decode())
    
    #DEMO SIG FORGING
    m1 = bytes_to_int(b"Hi Bob This is Alice")
    m2 = bytes_to_int(b"How are you doing?")
    
    sig1 = pow(m1, priv["d"], pub["n"])
    sig2 = pow(m2, priv["d"], pub["n"])
    
    sig3 = calcuate_sig_scheme(sig1, sig2, pub["n"])
    
    # Verify using m3 = m1*m2 mod n
    m3 = (m1 * m2) % pub["n"]
    print("sig1 valid:", verify_signature(sig1, m1, pub))
    print("sig2 valid:", verify_signature(sig2, m2, pub))
    print("sig3 valid (forged):", verify_signature(sig3, m3, pub))
    
    m3_from_sig = pow(sig3, pub["e"], pub["n"])  # should equal m3
    assert m3_from_sig == m3
    
    print(verify_signature(sig1, m1, pub)) 
    print(verify_signature(sig2, m2, pub)) 
    print(verify_signature(sig3, m3, pub)) 

    print("All signatures verified.")
    

if __name__ == "__main__":
    main()

