import jwt
import argparse
import sys

def decode_jwt(token, secret_key=None):
    try:
        if secret_key:
            # Decode and verify the JWT token's signature
            decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
            print("Decoded JWT with Signature Verification:")
        else:
            # Decode without verifying the signature
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            print("Decoded JWT without Signature Verification:")

        print(f"\n\n{decoded_token}\n")
        analyze_token(decoded_token)

    except jwt.ExpiredSignatureError:
        print("Error: The token has expired.")
    except jwt.InvalidTokenError:
        print("Error: The token is invalid.")

def analyze_token(decoded_token):
    print("\nToken Analysis:")

    # Detect and describe standard JWT claims
    if 'iss' in decoded_token:
        print(f"- Issuer (iss): {decoded_token['iss']}")
        print(f"  The token was issued by: {decoded_token['iss']}")

    if 'sub' in decoded_token:
        print(f"- Subject (sub): {decoded_token['sub']}")
        print(f"  The token is intended for the subject: {decoded_token['sub']}")

    if 'aud' in decoded_token:
        print(f"- Audience (aud): {decoded_token['aud']}")
        print(f"  The token is intended for the audience: {decoded_token['aud']}")

    if 'scope' in decoded_token:
        print(f"- Scope (scope): {decoded_token['scope']}")
        print("  The token has the following permissions or access scope:")
        for scope in decoded_token['scope'].split():
            print(f"    - {scope}")

    if 'role' in decoded_token:
        print(f"- Role (role): {decoded_token['role']}")
        print("  The token is associated with the following roles:")
        if isinstance(decoded_token['role'], list):
            for role in decoded_token['role']:
                print(f"    - {role}")
        else:
            print(f"    - {decoded_token['role']}")

def main():
    parser = argparse.ArgumentParser(description="Decode a JWT token.")
    parser.add_argument("token", help="The JWT token to decode")
    parser.add_argument("--secret", help="The secret key to verify the token's signature (optional)")

    args = parser.parse_args()

    decode_jwt(args.token, args.secret)

if __name__ == "__main__":
    main()
