from fastapi import APIRouter, Body, HTTPException, Depends
from models.user import User,UserSchema,UserLoginSchema
from config.db import conn 
from schemas.user import serializeDict, serializeList
from bson import ObjectId
from app.auth.jwt_handler import signJWT, decodeJWT 
from app.auth.jwt_bearer import jwtBearer
import bcrypt
user = APIRouter() 

#user signup
@user.post("/signup",tags=["user"])
async def user_signup(user: UserSchema = Body(default=None)):
    print(user)
    if check_user_signup(user):
        user.password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())
        # print(user)
        conn.local.user.insert_one(dict(user))
        return signJWT(user.email)
    else:
        raise HTTPException(status_code=409, detail="Email already exist")

#user login       
@user.post("/login",tags = ["user"])
async def user_login(user: UserLoginSchema = Body(default = None)):
    if check_user_login(user):
        return signJWT(user.email)
    else:
        raise HTTPException(status_code=401, detail="Invalid Login")


#validating functions for login and signup
def check_user_signup(data: UserSchema):
    signupQuery = serializeList(conn.local.user.find({"email":data.email}))
    if(len(signupQuery) == 0):
        return True
    else:
        False

def check_user_login(data: UserLoginSchema):
    loginQuery = serializeList(conn.local.user.find({"email": data.email}))
    print(loginQuery[0]["password"], bcrypt.hashpw(data.password.encode("utf-8"), bcrypt.gensalt()))
    if len(loginQuery) == 1 and loginQuery[0]["email"] == data.email and bcrypt.checkpw(data.password.encode('utf-8'), loginQuery[0]["password"]) :
        return True
    else:
        return False

#example route
@user.get("/test", tags=["test"])
def greet():
    return {"hello":"world"}

@user.get('/',  dependencies=[Depends(jwtBearer())])
async def find_all_users(token: str = Depends(jwtBearer())):
    print("get all usres: ", decodeJWT(token))
    
    # decode_token = jwt.decode(jwtBearer().credentials, JWT_SECRET, algorithms = [JWT_ALGORITHM])
    return serializeList(conn.local.user.find())

@user.get('/{id}')
async def find_one_user(id):
    return serializeDict(conn.local.user.find_one({"_id":ObjectId(id)}))

@user.put('/{id}')
async def update_user(id,user: User):
    conn.local.user.find_one_and_update({"_id":ObjectId(id)},{
        "$set":dict(user)
    })
    return serializeDict(conn.local.user.find_one({"_id":ObjectId(id)}))

@user.delete("/{id}", dependencies=[Depends(jwtBearer())] )
async def delete_user(id,user: User):
    return serializeDict(conn.local.user.find_one_and_delete({"_id":ObjectId(id)}))
