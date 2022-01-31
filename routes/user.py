from typing import Optional
from fastapi import APIRouter, Body, HTTPException, Depends
from models.user import UserSchema, UserLoginSchema
from config.db import conn
from schemas.user import serializeDict, serializeList, usersEntity
from bson import ObjectId
from app.auth.jwt_handler import signJWT, decodeJWT
from app.auth.jwt_bearer import jwtBearer
import bcrypt

user = APIRouter()

# user signup


@user.post("/signup", tags=["User authentication"], name="User Signup", description="Registers a user with the given credentials and returns an authenticaion token")
async def user_signup(user: UserSchema = Body(default=None)):
    if check_user_signup(user):
        user.password = bcrypt.hashpw(
            user.password.encode("utf-8"), bcrypt.gensalt())
        # print(user)
        conn["user"].insert_one(dict(user))
        # print(conn["user"].find())
        return signJWT(user.email, user.name)
    else:
        raise HTTPException(status_code=409, detail="Email already exist")

# user login


@user.post("/login", tags=["User authentication"], name="User Login", description="Logs in the user, and returns an authentication token")
async def user_login(user: UserLoginSchema = Body(default=None)):
    userData = check_user_login(user)
    if(userData):
        return signJWT(user.email, userData[0]["name"])
    else:
        raise HTTPException(status_code=401, detail="Invalid Login!")


# basic user operations


@user.get('/getUsers', tags=["User"],  dependencies=[Depends(jwtBearer())], name="Get list of users matching quary param", description="Get list of users matching quary param")
async def find_all_users(searchString: Optional[str] = None, token: str = Depends(jwtBearer())):
    if(searchString != None):
        return usersEntity(conn.user.find({"email": {'$regex': searchString}}))
    else:
        return usersEntity(conn.user.find())
    # return usersEntity(conn.user.find())


@user.get('/user/{id}', tags=["User"],  dependencies=[Depends(jwtBearer())], name="Find a user by id", description="Find a user by id")
async def find_one_user(id):
    return serializeDict(conn.user.find_one({"_id": ObjectId(id)}))


@user.delete("/user/{id}", tags=["User"], dependencies=[Depends(jwtBearer())])
async def delete_user(id, token: str = Depends(jwtBearer())):
    try:
        userQuery = conn.user.find_one({"email": decodeJWT(token)["userID"]})
        print(userQuery)
        if(userQuery["email"] == decodeJWT(token)["userID"]):
            try:
                conn.user.find_one_and_delete({"_id": ObjectId(id)})
                return {"msg": "deleted successfully"}
            except Exception as e:
                print(e)
                raise HTTPException(status_code=404, detail="User not found")
        else:
            raise HTTPException(status_code=403, detail="Forbidden!")
    except Exception as e:
        print(e)
        raise HTTPException(status_code=404, detail="User not found")

# Helper Functions
# validating functions for login and signup


def check_user_signup(data: UserSchema):
    signupQuery = serializeList(conn.user.find({"email": data.email}))
    if(len(signupQuery) == 0):
        return True
    else:
        False


def check_user_login(data: UserLoginSchema):
    loginQuery = serializeList(conn.user.find({"email": data.email}))
    print(loginQuery[0]["password"], bcrypt.hashpw(
        data.password.encode("utf-8"), bcrypt.gensalt()))
    if len(loginQuery) == 1 and loginQuery[0]["email"] == data.email and bcrypt.checkpw(data.password.encode('utf-8'), loginQuery[0]["password"]):
        return loginQuery
    else:
        raise HTTPException(
            status_code=401, detail="Invalid login credentials")
