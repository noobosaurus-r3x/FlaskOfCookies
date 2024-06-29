#!/usr/bin/env python3
"""Flask Of Cookies - Encode/Decode Flask Cookies with Brute-force Capability"""
"""Author: Noobosaurus R3x - Inspired by flask-session-cookie-manager by Wilson Sumanang, Alexandre Zanni"""

import argparse
import base64
import ast
import hashlib
import sys
from itsdangerous import URLSafeTimedSerializer, BadSignature, TimestampSigner
from flask.sessions import SecureCookieSessionInterface
from flask.json.tag import TaggedJSONSerializer

# Define the default salt used by Flask
DEFAULT_SALT = 'cookie-session'

class MockApp:
    def __init__(self, secret_key):
        self.secret_key = secret_key

def add_padding(cookie_value):
    """Add padding to the base64-encoded cookie value"""
    missing_padding = len(cookie_value) % 4
    if missing_padding != 0:
        cookie_value += "=" * (4 - missing_padding)
    return cookie_value

def get_serializer(secret, salt=DEFAULT_SALT):
    """Get the serializer for signing and verifying"""
    return URLSafeTimedSerializer(
        secret_key=secret,
        salt=salt,
        serializer=TaggedJSONSerializer(),
        signer=TimestampSigner,
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1
        }
    )

def encode(secret_key, session_cookie_structure):
    """Encode a Flask session cookie"""
    try:
        app = MockApp(secret_key)
        session_cookie_structure = ast.literal_eval(session_cookie_structure)
        serializer = get_serializer(app.secret_key)
        return serializer.dumps(session_cookie_structure)
    except ValueError as e:
        return f"[Encoding error] Input isn't a valid Python dictionary: {str(e)}"
    except Exception as e:
        return f"[Encoding error] {str(e)}"

def decode(session_cookie_value, secret_key=None):
    """Decode a Flask cookie"""
    try:
        if secret_key is None:
            payload = session_cookie_value

            if payload.startswith('.'):
                payload = payload[1:]

            data = payload.split(".")[0]
            data = add_padding(data)
            data = base64.urlsafe_b64decode(data)

            return data.decode('utf-8')
        else:
            app = MockApp(secret_key)
            serializer = get_serializer(app.secret_key)
            return serializer.loads(session_cookie_value)
    except BadSignature as e:
        return f"[Decoding error] Input isn't a valid Flask session cookie: {str(e)}"
    except Exception as e:
        return f"[Decoding error] {str(e)}"

def brute_force(cookie_value, wordlist_path, salt=DEFAULT_SALT):
    """Brute-force the secret key using a wordlist"""
    attempts = 0
    max_length = 0
    try:
        with open(wordlist_path, 'r') as wordlist:
            for secret_key in wordlist:
                secret_key = secret_key.strip()
                attempts += 1
                try:
                    app = MockApp(secret_key)
                    serializer = get_serializer(app.secret_key, salt)
                    serializer.loads(cookie_value)
                    print(f"\r{' ' * max_length}", end='', flush=True)  # Clear the line
                    print(f"\rAttempt #{attempts}: Success with secret key: {secret_key}")
                    return secret_key
                except BadSignature:
                    output = f"Attempt #{attempts}: Failed with secret key: {secret_key}"
                    max_length = max(max_length, len(output))
                    print(f"\r{output.ljust(max_length)}", end='', flush=True)
                    continue
        print()  # Move to the next line after completion
        return None
    except Exception as e:
        return f"[Brute-force error] {str(e)}"

def main():
    parser = argparse.ArgumentParser(
        description='Flask Cookie Decoder/Encoder with Brute-force Capability',
        epilog="Inspired by 'Flask Session Cookie Decoder/Encoder' by Wilson Sumanang, Alexandre Zanni"
    )
    subparsers = parser.add_subparsers(help='sub-command help', dest='subcommand')

    parser_encode = subparsers.add_parser('encode', help='encode')
    parser_encode.add_argument('-s', '--secret-key', metavar='<string>',
                               help='Secret key', required=True)
    parser_encode.add_argument('-t', '--cookie-structure', metavar='<string>',
                               help='Session cookie structure', required=True)

    parser_decode = subparsers.add_parser('decode', help='decode')
    parser_decode.add_argument('-s', '--secret-key', metavar='<string>',
                               help='Secret key', required=False)
    parser_decode.add_argument('-c', '--cookie-value', metavar='<string>',
                               help='Session cookie value', required=True)

    parser_bruteforce = subparsers.add_parser('bruteforce', help='bruteforce')
    parser_bruteforce.add_argument('-c', '--cookie-value', metavar='<string>',
                                   help='Session cookie value', required=True)
    parser_bruteforce.add_argument('-w', '--wordlist', metavar='<path>',
                                   help='Path to the wordlist', required=True)
    parser_bruteforce.add_argument('--salt', default=DEFAULT_SALT, metavar='<string>',
                                   help='Custom salt (default: cookie-session)')

    args = parser.parse_args()

    if args.subcommand == 'encode':
        print(encode(args.secret_key, args.cookie_structure))
    elif args.subcommand == 'decode':
        print(decode(args.cookie_value, args.secret_key))
    elif args.subcommand == 'bruteforce':
        secret_key = brute_force(args.cookie_value, args.wordlist, args.salt)
        if secret_key:
            print(f"\nSecret key found: {secret_key}")
        else:
            print("\nSecret key not found")

if __name__ == "__main__":
    main()
