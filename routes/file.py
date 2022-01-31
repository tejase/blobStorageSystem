from fastapi import APIRouter, Body, HTTPException, Depends, UploadFile, File
from models.user import FileShareSchema, FileRenameSchema, AccessDeleteSchema
from config.db import conn
from schemas.user import serializeDict, serializeList
from bson import ObjectId
from app.auth.jwt_handler import decodeJWT
from app.auth.jwt_bearer import jwtBearer
from motor.motor_asyncio import AsyncIOMotorGridFSBucket, AsyncIOMotorClient
from fastapi.responses import StreamingResponse
from decouple import config

file = APIRouter()

# Upload File


@file.post("/file/upload", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Upload a file", description="Uploads file corresponding to authenticated user and returns fileID")
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


@file.get("/file/{FID}", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Get a file", description="Gets file as streaming response, with file_id")
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


@file.get("/file/{FID}/details", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get details of a file", description="Gets metadata of a file from file_id")
async def getFileDetails(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID) in ["Owner", "Editor", "Viewer"]):
        fileQuery = conn.fs.files.find_one({"_id": ObjectId(FID)})
        # print(fileQuery)
        return serializeDict(fileQuery)
    return {}

# Get Role of a user corresponding to a file


@file.get("/file/{FID}/role", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get Role", description="Gets the role of the user corresponding to a file")
async def getFileRole(FID, token: str = Depends(jwtBearer())):
    return {"role": getRole(decodeJWT(token)["userID"], FID)}

# Get all files corresponding to an user


@file.get("/files", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get all files", description="Returns all the files the user has access to")
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


@file.post("/file/share", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Share file/ Change Role", description="This endpoint can be used to share a file to any user with role, and also to update user's role of a file which has already been shared. Can be used only by owner of a file. Available roles for a file are Owner, Editor, Viewer")
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


@file.get("/file/{FID}/users", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Get users having access to a file", description="Returns the list of users having access to a file along with their roles")
async def getUsersSharingFile(FID, token: str = Depends(jwtBearer())):
    if(getRole(decodeJWT(token)["userID"], FID)):
        return (getAccessList(FID))

# Remove access of a file


@file.delete("/file/{FID}/access", dependencies=[Depends(jwtBearer())], tags={"File Managment"}, name="Remove file access", description="Removes the access to file from a user. Can be only performed by owner of a file")
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


@file.put("/file/{FID}/rename", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Rename a file", description="Updates name of a file. Can be used only by Owner or Editor of a file")
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


@file.delete("/file/{FID}", dependencies=[Depends(jwtBearer())], tags=["File Managment"], name="Delete a file", description="Deletes a file. Can only be performed by owner of the file")
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

# Helper functions


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
