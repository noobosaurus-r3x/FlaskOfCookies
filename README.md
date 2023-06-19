# Flask Of Cookies - Encode/Decode Flask Cookies

Flask Of Cookies is a Python script that allows you to encode and decode Flask session cookies. It provides a command-line interface for encoding and decoding session cookies with or without a secret key.
inspired by the `flask-session-cookie-manager` project by Wilson Sumanang and Alexandre ZANNI. 

## Features

- Encode a Flask session cookie using a secret key and session cookie structure.
- Decode a Flask session cookie with or without a secret key.

## Usage

To use Flask Of Cookies, follow these steps:

1. Clone the repository or download the `FOC.py` file.
2. Ensure you have Python 3 installed on your system.
3. Install the required dependencies by running the following command:
`pip install flask itsdangerous`
4. Open a terminal or command prompt and navigate to the directory where `FOC.py` is located.
5. Run the script with the desired subcommand:

- To display the help message and available options, use the `-h` option:
```
  python3 FOC.py -h
```

- To encode a Flask session cookie, use the `encode` subcommand:
  ```
  python3 FOC.py encode -s <secret_key> -t <cookie_structure>
  ```
  - Replace `<secret_key>` with your Flask secret key.
  - Replace `<cookie_structure>` with the session cookie structure as a valid Python dictionary string. for example : '{"number":"326410031505","username":"admin"}'


- To decode a Flask session cookie with the secret key, use the `decode` subcommand:
  ```
  python3 FOC.py decode -s <secret_key> -c <cookie_value>
  ```
  - Replace `<secret_key>` with your Flask secret key.
  - Replace `<cookie_value>` with the session cookie value to decode.

- To decode a Flask session cookie without the secret key, use the `decode` subcommand:
  ```
  python3 FOC.py decode -c <cookie_value>
  ```
  - Replace `<cookie_value>` with the session cookie value to decode.

6. The encoded or decoded result will be printed in the terminal.

## Acknowledgements

Flask Of Cookies was inspired by the `flask-session-cookie-manager` project by Wilson Sumanang and Alexandre ZANNI.
https://github.com/noraj/flask-session-cookie-manager


