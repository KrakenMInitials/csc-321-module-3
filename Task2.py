from Crypto.Cipher import AES
import hashlib
import random
from hashlib import sha256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


G_hex = """A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5"""
G_cleaned = G_hex.replace("\n", "").replace(" ", "")
G = int(G_cleaned, 16)

p_hex = """B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371"""
p_cleaned = p_hex.replace("\n", "").replace(" ", "")
p = int(p_cleaned, 16)

IV = get_random_bytes(16) 

#THESE ARE PRIVATE (MALLORY DONT KNOW)
ALICE_SECRET_KEY = random.randint(1, p-2)
BOB_SECRET_KEY = random.randint(1, p-2)
ALICES_MESSAGE = "Hi Bob!"
BOBS_MESSAGE = "Hi Alice!"


def main():  
    #GET A & B
    A = pow(G, ALICE_SECRET_KEY, p) #A = (g^a) mod p   ALICE'S PUBLIC KEY (pt.1)
    B = pow(G, BOB_SECRET_KEY, p) #B = (g^b) mod p     BOB'S PUBLIC KEY (pt.1)

    #Mallory attack demonstration
    A = p
    B = p

    # Bob takes Alices Public Key and calculates common_key
    bobs_shared_secret = pow(A, BOB_SECRET_KEY, p) # (A^b) mod p 
    alices_shared_secret = pow(B, ALICE_SECRET_KEY, p) #(B^a) mod p
    
    print("Alice private key(XA): ", ALICE_SECRET_KEY)
    print("Bob private key(XB): " , BOB_SECRET_KEY)
    print("Alice public key(YA): " , A)
    print("Bob public key(YB): " , B)
    print()

    #Alice and Bob's shared secret wll always be 0 due to Mallory
    print("Alice's computed shared secret: ", alices_shared_secret)
    print("Bob's computed shared secret:", bobs_shared_secret)

    #Alice's derived key
    alices_len = (alices_shared_secret.bit_length()+7)//8
    alices_symmetric_key = alices_shared_secret.to_bytes(alices_len, "big")
    alices_key = hashlib.sha256(alices_symmetric_key).digest() #create a hash of the secret 
    alices_key = alices_key[:16] #truncate to 16 bytes
    print("Alice's derived key", alices_key.hex())

    #Bob's derived key
    bobs_len = (bobs_shared_secret.bit_length()+7)//8
    bobs_symmetric_key = bobs_shared_secret.to_bytes(bobs_len, "big")
    bobs_key = hashlib.sha256(bobs_symmetric_key).digest() #create a hash of the secret 
    bobs_key = bobs_key[:16] #truncate to 16 bytes
    print("Bob's derived key", bobs_key.hex())

    print()

    #Mallory's derived key
    mallory_shared_secret = 0
    mallory_len = (mallory_shared_secret.bit_length()+7)//8
    mallory_symmetric_key = mallory_shared_secret.to_bytes(mallory_len, "big")
    mallory_key = hashlib.sha256(mallory_symmetric_key).digest()
    mallory_key = mallory_key[:16]
    print("Mallory's derived key", mallory_key.hex())
    print("Mallory determines the shared secret: ", mallory_shared_secret)

    print(f"All parties have the same key: {alices_key == bobs_key == mallory_key}")
    print()

    #Encrypt Alice's Message
    alice_encoded_message = ALICES_MESSAGE.encode() #encode to bytes
    alice_cipher = AES.new(alices_key, AES.MODE_CBC, IV)
    alice_length = 16 - (len(alice_encoded_message) % 16)
    alice_padded = alice_encoded_message + bytes([alice_length]) * alice_length
    alice_ciphertext = alice_cipher.encrypt(alice_padded)
    print("Alice's message: " , ALICES_MESSAGE)
    print("Alice's IV: ", IV)
    print("Alice's ciphertext: " , alice_ciphertext.hex())

    #Mallory decrypting Alice's message
    mallory_alice_decrypt_cipher = AES.new(mallory_key, AES.MODE_CBC, IV)
    mallory_alice_decrypted = mallory_alice_decrypt_cipher.decrypt(alice_ciphertext)
    mallory_alice_decrypt_pad_len = mallory_alice_decrypted[-1]
    alice_plaintext = mallory_alice_decrypted[:-mallory_alice_decrypt_pad_len].decode()
    print("Mallory decrypts c0: " , alice_plaintext)

    print()

    #Encrypt Bob's Message
    bob_encoded_message = BOBS_MESSAGE.encode() #encode to bytes
    bob_cipher = AES.new(bobs_key, AES.MODE_CBC, IV)
    bob_length = 16 - (len(bob_encoded_message) % 16)
    bob_padded = bob_encoded_message + bytes([bob_length]) * bob_length
    bob_ciphertext = bob_cipher.encrypt(bob_padded)
    print("Bob's message: " , BOBS_MESSAGE)
    print("Bob's IV: ", IV)
    print("Bob's ciphertext: " , bob_ciphertext.hex())

    #decrypting Alice's message
    mallory_bob_decrypt_cipher = AES.new(mallory_key, AES.MODE_CBC, IV)
    mallory_bob_decrypted = mallory_bob_decrypt_cipher.decrypt(bob_ciphertext)
    mallory_bob_decrypt_pad_len = mallory_bob_decrypted[-1]
    bob_plaintext = mallory_bob_decrypted[:-mallory_bob_decrypt_pad_len].decode()
    print("Mallory decrypts c1: " , bob_plaintext)



if __name__ == "__main__": 
    main()