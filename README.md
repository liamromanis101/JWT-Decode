# JWT-Decode
Decodes JWT tokens and performs some analysis on the decoded values. 

## Usage
python3 decode_jwt.py your_jwt_token_here  
or  
python3 decode_jwt.py your_jwt_token_here --secret your_secret_key_here  

## Requirements
Python3  
pip install argparse sys PyJWT  

## Description
This script will decode a provided JWT token, print out the decoded value and perform some analysis:  

Token Analysis Function (analyze_token):  
	•	iss (Issuer): Identifies who issued the token. This could be the identity provider (e.g., AWS Cognito, Google).  
	•	sub (Subject): Represents the subject or principal that the token is issued to. Often, this is the user ID.  
	•	aud (Audience): Specifies the intended audience of the token, typically an application or API.  
	•	scope (Scope): Defines the permissions or access level granted by the token. This is usually a space-separated list of strings.  
	•	role (Role): Lists the roles assigned to the token bearer. This could define what actions the bearer can perform.  

# JWT-Recode
Creates a new JWT token from an existing one adding in values for iss, sub, aud, scope and role.  

## Usage

python3 jwt-recode.py <your_jwt_token>  
or  
python3 jwt-recode.py <your_jwt_token> --secret <your_secret_key>  

## Requirements
Python3  
pip install argparse sys PyJWT datetime

## Description
This script will create a new JWT token from an existing one and change or add in values for iss, sub, aud, scope and role.   

For example, you may want to change the role to allow access to other services or change the role to 'admin'. 

# JWT-Crack
Uses a dictionary to crack JWT signatures generated with HS256, HS384 and HS512 algorithms. 

## Usage

python3 jwt-crack.py <jwt_token> <path_to_dictionary_file>  

## Requirements

pip install base64 hashlib hmac jwt argparse json sys  

## Description
This script can be used to crack the signatures of JWT tokens generated using HS256, HS384 and HS512 algorithms. The script will pad the values taken from the dictionary up to the length required by each algorithm:  

HS256: 32 Bytes  
HS384: 48 Bytes  
HS512: 64 Bytes  

# JWT-Gen
Usful for testing purposes as you will known the value of the secret. 

## Usage

python3 jwt-gen.py <json_jwt_content> <secret> <algorithm>  

i.e. python3 jwt-gen.py '{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}' 'password1' HS256  

## Requirements 

pip install base64 hashlib hmac jwt argparse json

## Description
Simple script for creating example jwt tokens with signatures created with a known secret for testing the other scripts.  

Currently this script is not producing 100% valid JWT tokens, working on it. 
