import base64
import hashlib
import hmac
import jwt
import argparse
import json

def base64url_encode(data):
    """Base64url encode the input data."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def pad_key(key, length):
    """Pad or truncate the key to the specified length."""
    key_bytes = key.encode('utf-8')
    if len(key_bytes) > length:
        return key_bytes[:length]  # Truncate if longer
    return key_bytes.ljust(length, b'\x00')  # Pad with zeros if shorter

def create_jwt(payload, secret_key, algorithm):
    """Create a JWT with the specified payload, secret key, and algorithm."""
    secret_key = pad_key(secret_key, {'HS256': 32, 'HS384': 48, 'HS512': 64}[algorithm])
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token

def main():
    parser = argparse.ArgumentParser(description="Create a JWT token with a padded secret key.")
    parser.add_argument("payload", help="Payload for the JWT as a JSON string")
    parser.add_argument("secret_key", help="Secret key for signing the JWT")
    parser.add_argument("algorithm", choices=['HS256', 'HS384', 'HS512'], help="Algorithm for signing the JWT")

    args = parser.parse_args()

    # Load and parse the payload
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError:
        print("Invalid JSON payload.")
        return

    # Create JWT token
    try:
        token = create_jwt(payload, args.secret_key, args.algorithm)
        print(f"Generated JWT Token: {token}")
    except Exception as e:
        print(f"Error creating JWT token: {e}")

if __name__ == "__main__":
    main()
