from urllib.parse import urlencode, urlparse, urlunparse
import os
from dotenv import load_dotenv
import secrets 
import hashlib
import base64

load_dotenv()

client_id = os.getenv("CLIENT_ID")
print(f"Client ID: {client_id}")
redirect_uri = "http://127.0.0.1:3000"
scope = 'user-read-private user-read-email'

auth_base_url = "https://accounts.spotify.com/authorize"

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
print(f"Hashed code verifier: {hashed}")
codeChallenge = base64url_encode(hashed)
print(f"Code challenge: {codeChallenge}")

params = {
    'response_type':'code',
    'client_id':client_id,
    'scope':scope,
    'code_challenge_method':'S256',
    'code_challenge':codeChallenge,
    'redirect_uri':redirect_uri
}

query_string = urlencode(params)
full_auth_url = f"{auth_base_url}?{query_string}"

print(f"Direct the user to: {full_auth_url}")