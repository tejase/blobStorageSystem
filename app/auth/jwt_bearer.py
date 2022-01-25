#Check whether request is authorized or not
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .jwt_handler import decodeJWT

class jwtBearer(HTTPBearer):
    def __init__(self, auto_Error: bool = True):
        super(jwtBearer, self).__init__(auto_error = auto_Error)
    
    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(jwtBearer, self).__call__(request)
        if credentials:
            print(credentials)
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code = 403, detail="invalid or expired token")
            if self.verify_jwt(credentials.credentials):
                return credentials.credentials
            else:
                raise HTTPException(status_code = 403, detail="invalid or expired token")
        else:
            raise HTTPException(status_code = 403, detail="Invalid or expired token")

    def verify_jwt(self, jwtoken: str):
        isTokenValid: bool = False #false flag
        payload = decodeJWT(jwtoken)
        if payload:    
            isTokenValid = True
        return isTokenValid

 
