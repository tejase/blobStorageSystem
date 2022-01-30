from ast import Str
from email.policy import EmailPolicy
import time
import jwt
from decouple import config

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")

# returns generated tokens


def token_response(token: str, email: str, name: str):
    return {
        "access token": token,
        "email": email,
        "name": name
    }

# used to signing the JWT token


def signJWT(email: str, name: str):
    payload = {
        "userID": email,
        "expiry": time.time() + 60000
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token_response(token, email, name)


def decodeJWT(token: str):
    try:
        decode_token = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decode_token if decode_token['expiry'] >= time.time() else None
    except Exception as e:
        print(e)
        print("INVALID TOKEN")
        return None
