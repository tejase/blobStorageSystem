from ast import Str
import time
import jwt
from decouple import config

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")

#returns generated tokens

def token_response(token: str):
    return {
        "access token": token
    }

#used to signing the JWT token
def signJWT(userID: str):
    payload = {
        "userID": userID,
        "expiry": time.time() + 600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM) 
    return token_response(token)

def decodeJWT(token: str):
    try:
        decode_token = jwt.decode(token, JWT_SECRET, algorithms = [JWT_ALGORITHM])
        return decode_token if decode_token['expiry'] >= time.time() else None
    except Exception as e:
        print(e)
        print("INVALID TOKEN")
        return None

