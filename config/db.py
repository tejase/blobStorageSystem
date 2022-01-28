from pymongo import MongoClient
from decouple import config

#local host connection
# conn = MongoClient()

uri = config("mongoDbUri")

client = MongoClient(uri, authSource="admin")
conn = client["database"]
