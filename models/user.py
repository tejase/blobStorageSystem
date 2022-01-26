from base64 import encode
from codecs import EncodedFile
from dataclasses import Field
from email.policy import default
from typing_extensions import Required
from pydantic import BaseModel, Field, EmailStr, validator


class User(BaseModel):
    name: str
    email: str
    password: str

class UserSchema(BaseModel):
    name: str = Field(Required = True)
    email: EmailStr = Field(Required = True)
    password: str = Field(Required = True)
    class Config:
        the_schema = {
            "user_demo":{
                "name":"Tejas",
                "email":"tej@gmail.com",
                "password":"somwethin"
            }
        }

    @validator('name')
    def username_alphanumeric(cls, v):
        assert v.isalpha(), 'Name can contain only alphabets'
        assert v != '', 'Name cant be empty'
        return v

    @validator('password', each_item=True)
    def check_password_not_empty(cls, v):
        assert v != '', 'Empty Password is not allowed.'
        assert len(v) > 4, 'Password must be minimum 4 characters'
        return v

class UserLoginSchema(BaseModel):
    email: EmailStr = Field(default=None)
    password: str = Field(default=None)
    class Config:
        the_schema = {
            "user_demo":{
                "email":"tej@gmail.com",
                "password":"somwethin"
            }
        }

class FileSchema(BaseModel):
    filename: str = Field(default=None)

class FileShareSchema(BaseModel):
    destinationEmail: EmailStr = Field(Required = True)    
    fileID: str = Field(Required = True)
    role: str = Field(Required = True)

    @validator('role')
    def validRoleCheck(cls, v):
        assert v in ["Owner","Editor","Viewer"], 'Available roles are Owner, Editor and Viewer'
        return v

class FileRenameSchema(BaseModel):
    newFileName: str = Field(Required = True)

    @validator('newFileName')
    def validateNewFileName(cls, v):
        assert len(v) < 25, 'File Name is too long'
        assert v.isalnum(), 'File can only contain alphanumeric characters'
        return v
