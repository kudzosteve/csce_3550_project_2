from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import sqlite3
import os

hostName = "localhost"
serverPort = 8080
db_file = os.path.abspath(os.path.join(os.getcwd(), "totally_not_my_privateKeys.db"))

def create_database():
    # Connect to database and create cursor
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()

    # Create keys table
    db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
    """)

    # Commit changes and close connection
    db_connect.commit()
    db_connect.close()

    # Check if database contains keys before generating
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()
    db_cursor.execute("SELECT COUNT(*) FROM keys")
    count = db_cursor.fetchone()[0]     # check the first row
    db_connect.close()

    # if there are no keys, generate them
    if count == 0:
        generate_keys()

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())  # expires in 1 hour
    expired_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())  # expires 1 hour ago

    # Establish connection to the database and create cursor
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()

    # Insert data into the database
    db_cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (sqlite3.Binary(pem), pem_timestamp))
    db_cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (sqlite3.Binary(expired_pem), expired_timestamp))

    # Commit changes to the database and close connection
    db_connect.commit()
    db_connect.close()

def get_key(expired=False):
    """Retrieve a key from the database based on expiry"""
    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()

    current_time = int(datetime.now(timezone.utc).timestamp())

    if expired:
        # Get an expired key using parameterized query
        db_cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
    else:
        # Get a valid key using parameterized query
        db_cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))

    results = db_cursor.fetchone()
    db_connect.close()
    return (results[0], bytes(results[1]), results[2]) if results else None

def get_all_valid_keys():
    """Retrieve all valid keys from the database"""
    current_time = int(datetime.now(timezone.utc).timestamp())

    db_connect = sqlite3.connect(db_file)
    db_cursor = db_connect.cursor()

    db_cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (current_time,))
    results = [(result[0], bytes(result[1]), result[2]) for result in db_cursor.fetchall()]
    db_cursor.close()
    return results

# Encode keys with base64 encoding
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Get a key based on the "expired" parameter
            use_expired = "expired" in params
            key_data = get_key(expired=use_expired)

            if key_data:
                kid, key, exp = key_data
                headers = {
                    "kid": str(kid)
                }
                if use_expired:
                    # Create a token that is already expired
                    token_exp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
                else:
                    # Create a token that expires in 1 hour
                    token_exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())

                token_payload = {
                    "user": "username",
                    "exp": token_exp
                }
                try:

                    # Load the private key
                    private_key = serialization.load_pem_private_key(key, password=None)
                    # Sign the token
                    encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(bytes(encoded_jwt, "utf-8"))
                    return
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(f"Error signing JWT: {str(e)}".encode('utf-8'))
                    return
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No suitable key found")
                return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Get all valid keys
            valid_keys = get_all_valid_keys()

            # Create JWKS response
            jwks = {"keys": []}

            for kid, key, exp in valid_keys:
                # Load the private key
                private_key = serialization.load_pem_private_key(key, password=None)
                numbers = private_key.public_key().public_numbers()     # Get the public key parameters

                jwks["keys"].append(
                        {
                            "alg": "RS256",
                            "kty": "RSA",
                            "use": "sig",
                            "kid": str(kid),
                            "n": int_to_base64(numbers.n),
                            "e": int_to_base64(numbers.e),
                        }
                )

            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    create_database()  # Set up the database
    if not os.path.isfile(db_file):
        print(f"Database not found: {db_file}")
        exit()

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()