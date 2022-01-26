from base64 import decode
from opcode import opname
from fastapi import APIRouter, Body, HTTPException, Depends, UploadFile, File, Request
from models.user import User,UserSchema,UserLoginSchema, FileShareSchema, FileRenameSchema
from config.db import conn 
from schemas.user import serializeDict, serializeList
from bson import ObjectId
from bson.binary import Binary
from app.auth.jwt_handler import signJWT, decodeJWT 
from app.auth.jwt_bearer import jwtBearer
import bcrypt
import shutil
from motor.motor_asyncio import AsyncIOMotorGridFSBucket, AsyncIOMotorClient
from fastapi.responses import StreamingResponse
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

#RoleAssert function
def getRole(email, fileID):
    try:
        accessQuery = conn.local.access.find({"email":email,"fileID": ObjectId(fileID)})
        print(accessQuery[0]["role"])
        return accessQuery[0]["role"]
    except Exception as e:
        print("fdssdf",e)



# @user.post("/files/upload", dependencies=[Depends(jwtBearer())], tags=["File Managment"])
# async def uploadFile(token: str = Depends(jwtBearer()), file: UploadFile = File(...)):
#     with open(file.filename,"rb") as buffer:
#         print(file.content)
#         # shutil.copyfileobj(file.filename, buffer)
 
#         encoded = Binary(buffer.read())
#         print(encoded)
        
#         _id = conn.local.files.insert_one({"filename": file.filename, "file": encoded, "description": "test" })
#         print("uploaded user detail: ", decodeJWT(token)["userID"])
#         conn.local.access.insert_one({"email": decodeJWT(token)["userID"], "fileID": _id.inserted_id , "role": "Owner"})
#     return {"file_name":file.filename}

#Upload File
@user.post("/file/upload", dependencies=[Depends(jwtBearer())], tags=["File Managment"])
async def uploadFile(token: str = Depends(jwtBearer()), file: UploadFile = File(...)):
    client = AsyncIOMotorClient('localhost', 27017)
    fs = AsyncIOMotorGridFSBucket(client.local)
    print(fs)
    print(file.filename, file.file, file, file.content_type)
    file_id = await fs.upload_from_stream(
        file.filename,
        file.file,
        # chunk_size_bytes=255*1024*1024, #default 255kB
        metadata={"contentType": file.content_type})
    conn.local.access.insert_one({"email": decodeJWT(token)["userID"], "fileID": file_id , "role": "Owner"})
    return {"file_name":file.filename, "file_ID":str(file_id)}

#Get a file with File_id
@user.get("/file/{FID}", dependencies=[Depends(jwtBearer())], tags=["File Managment"])
async def getFile(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner","Editor","Viewer"]):

        client = AsyncIOMotorClient('localhost', 27017)
        fs = AsyncIOMotorGridFSBucket(client.local)
        file = await fs.open_download_stream(ObjectId(FID))
        return StreamingResponse(file, media_type = file.metadata["contentType"])
    else:
        raise HTTPException(status_code=403, detail="Not enough role to access this File")

#Get all files corresponding to an user
@user.get("/files", dependencies=[Depends(jwtBearer())], tags={"File Managment"})
async def getAllFiles(token: str = Depends(jwtBearer())):
    #list of fileIDs corresponding to the user
    fileIDListQuery = conn.local.access.find({"email": decodeJWT(token)["userID"]})
    fileIDList = []
    fileIDListQuery = serializeList(fileIDListQuery)
    for each in fileIDListQuery:
        fileIDList.append(each["fileID"])
    fileQuery = conn.local.fs.files.find( { "_id" : {'$in' :fileIDList}})
    print(fileIDList)
    return(serializeList(fileQuery))

#Share file
@user.post("/file/share", dependencies=[Depends(jwtBearer())], tags=["File Managment"])
async def shareFile(data: FileShareSchema = Body(default=None), token: str = Depends(jwtBearer())):
    try:
        if(getRole(decodeJWT(token)["userID"], data.fileID) in ["Owner"]):
            conn.local.access.insert_one({"email": data.destinationEmail, "fileID":ObjectId(data.fileID) , "role": data.role})
            return {"msg":"File shared successfullly"}
        else:
            raise HTTPException(status_code=403, detail="Not enough permission to share this file")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to share the file")
    

#Rename a file
@user.post("/file/{FID}/rename", dependencies=[Depends(jwtBearer())], tags=["File Managment"])
async def renameFile(FID, data: FileRenameSchema = Body(default=None), token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner","Editor"]):
        client = AsyncIOMotorClient('localhost', 27017)
        fs = AsyncIOMotorGridFSBucket(client.local)
        try:
            await fs.rename(ObjectId(FID),data.newFileName)
            return{"msg":"Renamed successfully"}
        except Exception as e:
            print(e)
            raise HTTPException(status_code=500, detail="Rename failed, something went wrong!")
    else:
        raise HTTPException(status_code=403, detail="Not enough permission to edit the file")

#Delete a file
@user.delete("/file/{FID}", dependencies=[Depends(jwtBearer())], tags=["File Managment"])
async def deleteFile(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner","Editor"]):
        client = AsyncIOMotorClient('localhost', 27017)
        fs = AsyncIOMotorGridFSBucket(client.local)
        try:
            await fs.delete(ObjectId(FID))
            conn.local.access.delete_many({"fileID": ObjectId(FID)})
            return{"msg":"Deleted File successfully"}
        except Exception as e:
            print(e)
            raise HTTPException(status_code=500, detail="Deletion failed, something went wrong!")
    else:
        raise HTTPException(status_code=403, detail="Not enough permission to edit the file")
    


        

    

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
