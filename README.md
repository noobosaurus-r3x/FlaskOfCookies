
# Flask Of Cookies - Encode/Decode Flask Cookies

Flask Of Cookies is a Python script that allows you to encode and decode Flask session cookies, or to bruteforce the secret key. It provides a command-line interface for encoding and decoding session cookies with or without a secret key. 

## Features

- Encode a Flask session cookie using a secret key and session cookie structure.
- Decode a Flask session cookie with or without a secret key.
- Brute-force the secret key of a Flask session cookie using a wordlist.

## Installation

### Prerequisites

- Python 3.x must be installed on your system.
- Install the required dependencies with the following command:
  ```bash
  pip install Flask itsdangerous
  ```

### Clone the Repository

1. Clone the repository or download the `FOC.py` file.
   ```bash
   git clone https://github.com/noobosaurus-r3x/FlaskOfCookies
   cd FlaskOfCookies
   ```

## Usage

Open a terminal or command prompt and navigate to the directory where `FOC.py` is located.

### Display Help and Available Options

To display the help message and available options, use the `-h` option:
```bash
python3 FOC.py -h
```

### Encode a Flask Session Cookie

To encode a Flask session cookie, use the `encode` subcommand:
```bash
python3 FOC.py encode -s <secret_key> -t <cookie_structure>
```
- Replace `<secret_key>` with your Flask secret key.
- Replace `<cookie_structure>` with the session cookie structure as a valid Python dictionary string. For example: `"{'number':'326410031505','username':'admin'}"`

### Decode a Flask Session Cookie with the Secret Key

To decode a Flask session cookie with the secret key, use the `decode` subcommand:
```bash
python3 FOC.py decode -s <secret_key> -c <cookie_value>
```
- Replace `<secret_key>` with your Flask secret key.
- Replace `<cookie_value>` with the session cookie value to decode.

### Decode a Flask Session Cookie without the Secret Key

To decode a Flask session cookie without the secret key, use the `decode` subcommand:
```bash
python3 FOC.py decode -c <cookie_value>
```
- Replace `<cookie_value>` with the session cookie value to decode.

### Brute-force the Secret Key of a Flask Session Cookie

To brute-force the secret key of a Flask session cookie using a wordlist, use the `bruteforce` subcommand:
```bash
python3 FOC.py bruteforce -c <cookie_value> -w <path_to_wordlist>
```
- Replace `<cookie_value>` with the session cookie value.
- Replace `<path_to_wordlist>` with the path to your wordlist.

## Example

```bash
python3 FOC.py encode -s 'mysecretkey' -t "{'number':'326410031505','username':'admin'}"
python3 FOC.py decode -s 'mysecretkey' -c 'encoded_cookie_value'
python3 FOC.py decode -c 'encoded_cookie_value'
python3 FOC.py bruteforce -c 'encoded_cookie_value' -w '/path/to/wordlist.txt'
```

## Acknowledgements

Flask Of Cookies was inspired by the `flask-session-cookie-manager` project by Wilson Sumanang and Alexandre Zanni.
https://github.com/noraj/flask-session-cookie-manager

---
