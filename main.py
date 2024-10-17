import http.client
import urllib.parse
import json
import os
import hashlib
import hmac
import base64
import time

# Set up Kraken API key and secret
API_KEY = os.getenv('KRAKEN_API_KEY')  # Your API Key
API_SECRET = os.getenv('KRAKEN_API_SECRET')  # Your API Secret

def get_kraken_signature(urlpath, data, secret):
    postdata = urllib.parse.urlencode(data)
    encoded = (str(data['nonce']) + postdata).encode()
    message = urlpath.encode() + hashlib.sha256(encoded).digest()

    signature = hmac.new(base64.b64decode(secret), message, hashlib.sha512)
    sigdigest = base64.b64encode(signature.digest())

    return sigdigest.decode()

# Ensure the API key and secret are set
if not API_KEY or not API_SECRET:
    raise ValueError("API key or secret not found in environment variables.")

# Nonce (current timestamp in milliseconds)
nonce = str(int(time.time() * 1000))

# Set up payload (including nonce)
payload = {
    "nonce": nonce
}
encoded_payload = urllib.parse.urlencode(payload)

# Generate the API signature
api_sign = get_kraken_signature("/0/private/Balance", payload, API_SECRET)

# Debugging outputs for verification
print("Nonce:", nonce)
print("Encoded Payload:", encoded_payload)
print("API Key:", API_KEY)
print("API Sign:", api_sign)

# Set up headers (API-Key and API-Sign)
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
    'API-Key': API_KEY,
    'API-Sign': api_sign
}

# Set up connection to Kraken API
conn = http.client.HTTPSConnection("api.kraken.com")

# Send the POST request to the private balance endpoint
conn.request("POST", "/0/private/Balance", encoded_payload, headers)

# Get the response
res = conn.getresponse()
data = res.read()

# Decode the response
response_json = json.loads(data.decode("utf-8"))

print("Response:", response_json)
# Check if the balance is empty
if res.status == 200:
    if not response_json['result']:
        print("Your balance is empty.")
    else:
        print("Balance:", response_json['result'])
else:
    print(f"Error: {res.status} {res.reason}")



# Print the response (which contains your balance or an error)
print(data.decode("utf-8"))

# Optionally, handle errors
if res.status != 200:
    print(f"Error: {res.status} {res.reason}")
