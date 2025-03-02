import json
import sys
import os

from pymongo import MongoClient

docker_db = os.environ.get('DOCKER_DB', "false")

if docker_db == "true":
    print("using docker compose db")
    mongo_client = MongoClient("mongo")
else:
    print("using local db")
    mongo_client = MongoClient("localhost")

db = mongo_client["cse312"]

chat_collection = db["chat"]
session_collection = db["session"]
reaction_collection = db["reactions"]
userPass_collection = db["password"]
userAuth_collection = db["auth_token"]

'''
for mess in reaction_collection.find({}):
    print(mess)
'''
#chat_collection.delete_many({})
#session_collection.delete_many({})
#reaction_collection.delete_many({})
#userPass_collection.delete_many({})
#userAuth_collection.delete_many({})