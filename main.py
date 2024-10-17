import http.client
import urllib.parse
import json
import os
import hashlib
import hmac
import base64
import time

# Function to retrieve environment variables
def get_env_variable(name, default=None):
    """Fetches the environment variable or raises an error if not set."""
    value = os.getenv(name, default)
    if value is None:
        raise ValueError(f"Environment variable '{name}' not found.")
    return value

# Function to generate the Kraken API signature
def get_kraken_signature(urlpath, data, secret):
    """Generates the HMAC-SHA512 signature required by Kraken's API."""
    postdata = urllib.parse.urlencode(data)
    encoded = (str(data['nonce']) + postdata).encode()
    message = urlpath.encode() + hashlib.sha256(encoded).digest()

    signature = hmac.new(base64.b64decode(secret), message, hashlib.sha512)
    return base64.b64encode(signature.digest()).decode()

# Function to make the Kraken API request
def make_kraken_request(api_key, api_secret, url_path, payload):
    """Sends a request to Kraken's API and returns the parsed response."""
    # Add nonce to the payload
    nonce = str(int(time.time() * 1000))
    payload['nonce'] = nonce

    # Form-encode the payload
    encoded_payload = urllib.parse.urlencode(payload)

    # Generate the API signature
    api_sign = get_kraken_signature(url_path, payload, api_secret)

    # Set up headers (API-Key and API-Sign)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'API-Key': api_key,
        'API-Sign': api_sign
    }

    # Set up connection to Kraken API
    conn = http.client.HTTPSConnection("api.kraken.com")

    try:
        # Send the POST request to the specified endpoint
        conn.request("POST", url_path, encoded_payload, headers)

        # Get the response
        res = conn.getresponse()
        data = res.read()

        # Decode the response
        response_json = json.loads(data.decode("utf-8"))

        # Print the raw response for debugging
        print(f"Response: {response_json}")

        if res.status != 200:
            print(f"Error: {res.status} {res.reason}")
            return None

        return response_json
    except Exception as e:
        print(f"An error occurred during the API request: {str(e)}")
        return None
    finally:
        conn.close()

# Main function to check the balance
def check_kraken_balance():
    """Checks the account balance on Kraken and handles the response."""
    try:
        # Fetch API key and secret from environment variables
        API_KEY = get_env_variable('KRAKEN_API_KEY')
        API_SECRET = get_env_variable('KRAKEN_API_SECRET')

        # Define the endpoint path
        url_path = "/0/private/Balance"

        # Make the API request to get the account balance
        payload = {}
        response_json = make_kraken_request(API_KEY, API_SECRET, url_path, payload)

        # Handle and display the response
        if response_json:
            if 'error' in response_json and response_json['error']:
                print(f"API Error: {response_json['error']}")
            elif not response_json['result']:
                print("Your balance is empty.")
            else:
                print(f"Balance: {response_json['result']}")
        else:
            print("Failed to retrieve a valid response from Kraken.")
    except ValueError as ve:
        print(f"Configuration Error: {ve}")
    except Exception as ex:
        print(f"Unexpected Error: {str(ex)}")

# Entry point of the script
if __name__ == "__main__":
    check_kraken_balance()
