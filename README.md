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

