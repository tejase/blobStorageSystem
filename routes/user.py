from base64 import decode
from email.policy import HTTP
from opcode import opname
from typing import Optional
from fastapi import FastAPI, APIRouter, Body, HTTPException, Depends, UploadFile, File, Request
from models.user import User, UserSchema, UserLoginSchema, FileShareSchema, FileRenameSchema, AccessDeleteSchema
from config.db import conn
from schemas.user import serializeDict, serializeList, usersEntity
from bson import ObjectId
from bson.binary import Binary
from app.auth.jwt_handler import signJWT, decodeJWT
from app.auth.jwt_bearer import jwtBearer
import bcrypt
import shutil
from motor.motor_asyncio import AsyncIOMotorGridFSBucket, AsyncIOMotorClient
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from decouple import config

app = FastAPI()
user = APIRouter()

# cross origin reference
origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# user signup


@user.post("/signup", tags=["user"], name="User Signup", description="Registers a user with the given credentials and returns an authenticaion token")
async def user_signup(user: UserSchema = Body(default=None)):
    print("ASSSJHG", user)
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


@user.post("/login", tags=["user"], name="User Login", description="Logs in the user, and returns an authentication token")
async def user_login(user: UserLoginSchema = Body(default=None)):
    userData = check_user_login(user)
    if(userData):
        return signJWT(user.email, userData[0]["name"])
    else:
        raise HTTPException(status_code=401, detail="Invalid Login!")


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

# RoleAssert function


def getRole(email, fileID):
    try:
        accessQuery = conn.access.find(
            {"email": email, "fileID": ObjectId(fileID)})
        print(accessQuery[0]["role"])
        return accessQuery[0]["role"]
    except Exception as e:
        print("fdssdf", e)
        raise HTTPException(status_code=404, detail="File not found")


def getAccessList(fileID):
    try:
        accessQuery = serializeList(conn.access.find(
            {"fileID": ObjectId(fileID)}, {"fileID": 0}))
        print(accessQuery, "hello")
        return accessQuery

    except Exception as e:
        raise HTTPException(status_code=404, detail="Not found")

# Upload File


@user.post("/file/upload", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Upload a file", description="Uploads file corresponding to authenticated user and returns fileID")
async def uploadFile(token: str = Depends(jwtBearer()), file: UploadFile = File(...)):
    client = AsyncIOMotorClient(config("mongoDbUri"), 27017)
    fs = AsyncIOMotorGridFSBucket(client.database)
    print(fs)
    print(file.filename, file.file, file, file.content_type)
    file_id = await fs.upload_from_stream(
        file.filename,
        file.file,
        # chunk_size_bytes=255*1024*1024, #default 255kB
        metadata={"contentType": file.content_type})
    conn.access.insert_one(
        {"email": decodeJWT(token)["userID"], "fileID": file_id, "role": "Owner"})
    return {"file_name": file.filename, "file_ID": str(file_id)}

# Get a file with File_id


@user.get("/file/{FID}", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Get a file", description="Gets file as streaming response, with file_id")
async def getFile(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner", "Editor", "Viewer"]):

        client = AsyncIOMotorClient(config("mongoDbUri"), 27017)
        fs = AsyncIOMotorGridFSBucket(client.database)
        file = await fs.open_download_stream(ObjectId(FID))
        return StreamingResponse(file, headers={"Content-Disposition": file.filename}, media_type=file.metadata["contentType"])
    else:
        raise HTTPException(
            status_code=403, detail="Not enough role to access this File")

# Get file datails with file id


@user.get("/file/{FID}/details", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get details of a file", description="Gets metadata of a file from file_id")
async def getFileDetails(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner", "Editor", "Viewer"]):
        fileQuery = conn.fs.files.find_one({"_id": ObjectId(FID)})
        # print(fileQuery)
        return serializeDict(fileQuery)
    return {}

# Get Role of a user corresponding to a file


@user.get("/file/{FID}/role", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get Role", description="Gets the role of the user corresponding to a file")
async def getFileRole(FID, token: str = Depends(jwtBearer())):
    return {"role": getRole(decodeJWT(token)["userID"], FID)}

# Get all files corresponding to an user


@user.get("/files", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get all files", description="Returns all the files the user has access to")
async def getAllFiles(token: str = Depends(jwtBearer())):
    # list of fileIDs corresponding to the user
    fileIDListQuery = conn.access.find({"email": decodeJWT(token)["userID"]})
    fileIDList = []
    fileIDListQuery = serializeList(fileIDListQuery)
    for each in fileIDListQuery:
        fileIDList.append(each["fileID"])
    fileQuery = conn.fs.files.find({"_id": {'$in': fileIDList}})
    print(fileIDList)
    return(serializeList(fileQuery))

# Share file


@user.post("/file/share", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Share file/ Change Role", description="This endpoint can be used to share a file to any user with role, and also to update user's role of a file which has already been shared. Can be used only by owner of a file. Available roles for a file are Owner, Editor, Viewer")
async def shareFile(data: FileShareSchema = Body(default=None), token: str = Depends(jwtBearer())):
    try:
        if(data.destinationEmail != decodeJWT(token)["userID"] and getRole(decodeJWT(token)["userID"], data.fileID) in ["Owner"]):
            # conn.access.insert_one({"email": data.destinationEmail, "fileID":ObjectId(data.fileID) , "role": data.role})
            conn.access.update({"email": data.destinationEmail, "fileID": ObjectId(
                data.fileID)}, {"$set": {"role": data.role}}, upsert=True)
            return {"msg": "File shared successfullly"}
        else:
            raise HTTPException(
                status_code=403, detail="Not enough permission to share this file")
    except Exception as e:
        print("Exception in share file: ", e)
        raise HTTPException(status_code=500, detail="Failed to share the file")

# get users sharing a file


@user.get("/file/{FID}/users", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get users having access to a file", description="Returns the list of users having access to a file along with their roles")
async def getUsersSharingFile(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID)):
        return (getAccessList(FID))

# Remove access of a file


@user.delete("/file/{FID}/access", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Remove file access", description="Removes the access to file from a user. Can be only performed by owner of a file")
async def deleteAccess(FID, data: AccessDeleteSchema = Body(default=None), token: str = Depends(jwtBearer())):
    try:
        if(data.email != decodeJWT(token)["userID"] and getRole(decodeJWT(token)["userID"], FID) in ["Owner"]):
            try:
                conn.access.delete_one(
                    {"fileID": ObjectId(FID), "email": data.email})
                return {"msg": "Deleted access successfully!"}
            except Exception as e:
                raise HTTPException(
                    status_code=500, detail="Something went wrong in removing access")

    except Exception as e:
        print(e, "sdf")
        raise HTTPException(
            status_code=403, detail="Not enough permission to perform this action!")
    return {}

# Rename a file


@user.put("/file/{FID}/rename", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Rename a file", description="Updates name of a file. Can be used only by Owner or Editor of a file")
async def renameFile(FID, data: FileRenameSchema = Body(default=None), token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner", "Editor"]):
        client = AsyncIOMotorClient(config("mongoDbUri"), 27017)
        fs = AsyncIOMotorGridFSBucket(client.database)
        try:
            await fs.rename(ObjectId(FID), data.newFileName)
            return{"msg": "Renamed successfully"}
        except Exception as e:
            print(e)
            raise HTTPException(
                status_code=500, detail="Rename failed, something went wrong!")
    else:
        raise HTTPException(
            status_code=403, detail="Not enough permission to edit the file")

# Delete a file


@user.delete("/file/{FID}", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Delete a file", description="Deletes a file. Can only be performed by owner of the file")
async def deleteFile(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner"]):
        client = AsyncIOMotorClient(config("mongoDbUri"), 27017)
        fs = AsyncIOMotorGridFSBucket(client.database)
        try:
            await fs.delete(ObjectId(FID))
            conn.access.delete_many({"fileID": ObjectId(FID)})
            return{"msg": "Deleted File successfully"}
        except Exception as e:
            print(e)
            raise HTTPException(
                status_code=500, detail="Deletion failed, something went wrong!")
    else:
        raise HTTPException(
            status_code=403, detail="Not enough permission to edit the file")


# example route
@user.get("/test", tags=["test"])
def greet():
    return {"hello": "world"}


@user.get('/get-all-files',  dependencies=[Depends(jwtBearer())])
async def find_all_users(searchString: Optional[str] = None, token: str = Depends(jwtBearer())):
    if(searchString != None):
        return usersEntity(conn.user.find({"email": {'$regex': searchString}}))
    else:
        return usersEntity(conn.user.find())
    # return usersEntity(conn.user.find())


@user.get('/{id}')
async def find_one_user(id):
    return serializeDict(conn.user.find_one({"_id": ObjectId(id)}))


@user.put('/{id}')
async def update_user(id, user: User):
    conn.user.find_one_and_update({"_id": ObjectId(id)}, {
        "$set": dict(user)
    })
    return serializeDict(conn.user.find_one({"_id": ObjectId(id)}))


@user.delete("/{id}", dependencies=[Depends(jwtBearer())])
async def delete_user(id, user: User):
    return serializeDict(conn.user.find_one_and_delete({"_id": ObjectId(id)}))
