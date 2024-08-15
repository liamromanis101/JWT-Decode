import jwt
import argparse
import json
from datetime import datetime, timedelta

def decode_jwt(token, secret_key=None):
    try:
        if secret_key:
            decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"], options={"verify_signature": False})
        else:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
        
        print("\nDecoded JWT Token:")
        print(json.dumps(decoded_token, indent=4))
        return decoded_token
    except jwt.ExpiredSignatureError:
        print("Error: The token has expired.")
        return None
    except jwt.InvalidTokenError:
        print("Error: The token is invalid.")
        return None

def create_new_jwt(original_token, secret_key, iss, sub, aud, scope, role):
    try:
        # Decode the original token without verifying signature
        decoded_original = jwt.decode(original_token, options={"verify_signature": False})

        # Debug: Print decoded original token
        print("\nOriginal Token Payload for Debugging:")
        print(json.dumps(decoded_original, indent=4))

        # Convert datetime to timestamp if they exist
        iat = decoded_original.get("iat", datetime.utcnow())
        exp = decoded_original.get("exp", datetime.utcnow() + timedelta(hours=1))
        if isinstance(iat, datetime):
            iat = int(iat.timestamp())
        if isinstance(exp, datetime):
            exp = int(exp.timestamp())

        # Update the payload with new values
        new_payload = {
            **decoded_original,  # Copy existing payload
            "iss": str(iss),
            "sub": str(sub),
            "aud": str(aud),
            "scope": str(scope),
            "role": str(role),
            # Retain or set issued at and expiration times
            "iat": iat,
            "exp": exp
        }

        # Debug: Print new payload
        print("\nNew Payload for Debugging:")
        print(json.dumps(new_payload, indent=4))

        # Encode the new JWT token
        new_token = jwt.encode(new_payload, secret_key, algorithm="HS256")
        return new_token
    except Exception as e:
        print(f"Error creating new JWT: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Decode and recode a JWT token.")
    parser.add_argument("token", help="The JWT token to decode")
    parser.add_argument("--secret", help="The secret key to verify the token's signature (optional)")

    args = parser.parse_args()

    # Decode the original token
    decoded_token = decode_jwt(args.token, args.secret)
    if not decoded_token:
        return

    # Request new values for claims
    iss = input("Enter new issuer (iss): ").strip('"')
    sub = input("Enter new subject (sub): ").strip('"')
    aud = input("Enter new audience (aud): ").strip('"')
    scope = input("Enter new scope (scope): ").strip('"')
    role = input("Enter new role (role, comma-separated if multiple): ").strip('"')

    # Handle multiple roles if provided as a comma-separated string
    roles = [r.strip() for r in role.split(",")] if "," in role else role

    # Create the new JWT token
    new_token = create_new_jwt(args.token, args.secret or "default_secret_key", iss, sub, aud, scope, roles)
    
    if new_token:
        print("\nNew JWT Token:")
        print(new_token)

if __name__ == "__main__":
    main()
