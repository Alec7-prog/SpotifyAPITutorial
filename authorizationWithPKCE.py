import secrets 
import hashlib
import base64

def generateCodeVerifier():
    possible = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    return ''.join(secrets.choice(possible) for _ in range(64))

def sha256(plain):
    #encode to bytes
    data = plain.encode('utf-8')

    #create sha256 hash
    hash_object = hashlib.sha256(data)

    #return raw bytes of hash
    return hash_object.digest()

def base64url_encode(input_bytes):
    encoded = base64.urlsafe_b64encode(input_bytes)
    
    # turns the bytes into a string, .rstrip removes any '=' padding
    return encoded.rstrip(b'=').decode('utf-8')

hashed = sha256(generateCodeVerifier())
codeChallenge = base64url_encode(hashed)
print("Code Challenge:", codeChallenge)