import datetime
from util.response import Response
from util.database import chat_collection, session_collection, reaction_collection, userPass_collection, userAuth_collection, video_collection, drawing_collection
import uuid
import json
import requests
import bcrypt
from util.auth import validate_password, extract_credentials
import hashlib
from dotenv import load_dotenv
import os
from util.multipart import *
from util.websockets import compute_accept, generate_ws_frame, parse_ws_frame

state = ""
# This path is provided as an example of how to use the router
def hello_path(request, handler):
    res = Response()
    res.text("hello")
    handler.request.sendall(res.to_data())

def escapeContents(data):
    data = data.replace("&","&amp;")
    data = data.replace("<","&lt;")
    data = data.replace(">","&gt;")
    return data

def home(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/index.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def chat(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/chat.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def public(request, handler):
    file_path = "public" + request.path[len("/public"):]
    mime_type = "application/octet-stream"

    # Manually mapping file extensions to MIME types
    ext = file_path.split('.')[-1].lower()
    mime_map = {
        "html": "text/html",
        "css": "text/css",
        "js": "application/javascript",
        "jpg": "image/jpeg",
        #"jpeg": "image/jpeg",
        "png": "image/png",
        "ico": "image/x-icon",
        "gif": "image/gif",
        "svg": "image/svg+xml",
        "mp4": "video/mp4", 
        "webp": "image/webp"
    }
    
    # If we know the extension, set the correct MIME type
    if ext in mime_map:
        mime_type = mime_map[ext]
    with open(file_path, 'rb') as f:
        content = f.read()
        res = Response()
        head={}
        head["Content-Type"] = mime_type
        head["X-Content-Type-Options"] = "nosniff"
        res.headers(head)
        res.bytes(content) 
        handler.request.sendall(res.to_data())

def getC(request, handler):
    message = list(chat_collection.find())
    dictMes = {}
    mesL=[]
    for mess in message:
        d = {}
        d["author"] = mess["author"]
        check = session_collection.find_one(d)
        if check is None:
            profile_pic = requests.get("https://api.dicebear.com/9.x/thumbs/svg?seed=" + str(uuid.uuid4()))
            profURL = "public/imgs/profile-pics/" + str(uuid.uuid4()) + ".svg"
            with open(profURL, "wb") as file:
                file.write(profile_pic.content)
            c = {}
            c["nickname"] = mess["author"]
            c["author"] = mess["author"]
            c["imageURL"] = profURL
            session_collection.insert_one(c)
        auth = session_collection.find_one(d).get("nickname", mess["author"])
        prof = session_collection.find_one(d).get("imageURL", mess["author"])
        c = {}
        c["id"] = mess["id"]
        reactions = reaction_collection.find(c)
        a = {}
        
        for recUser in reactions:
            if recUser["reactions"] in a:
                a[recUser["reactions"]].append(recUser["author"])
            else:
                a[recUser["reactions"]] = [recUser["author"]]
            
    
        mesForm = {
            "author":mess["author"],
            "id":mess["id"],
            "content": mess["content"],
            "updated":mess["updated"],
            "reactions":a,
            "nickname":auth,
            "imageURL":prof
        }
        mesL.append(mesForm)
    dictMes["messages"] = mesL

    res = Response()
    res.json(dictMes)
    handler.request.sendall(res.to_data())
    
def postC(request, handler):
    res = Response()
    data = json.loads(request.body.decode("utf-8"))
    con = escapeContents(data.get("content"))
    if "auth_token" in request.cookies:
            auth_token = request.cookies["auth_token"]
            hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
            i = {}
            i["auth_token"] = hash_auth
            userID = userAuth_collection.find_one(i).get("id")
            filter = {}
            filter["id"] = userID
            auth = userPass_collection.find_one(filter).get("username")
    elif "session" in request.cookies:
        auth = request.cookies["session"]
    else:
        profile_pic = requests.get("https://api.dicebear.com/9.x/thumbs/svg?seed=" + str(uuid.uuid4()))
        profURL = "public/imgs/profile-pics/" + str(uuid.uuid4()) + ".svg"
        with open(profURL, "wb") as file:
            file.write(profile_pic.content)
        
        auth = str(uuid.uuid4())
        cookie={}
        cookie["session"] = auth + ";Max-Age=99999999999;HttpOnly" 
        res.cookies(cookie)
        d = {}
        d["author"] = auth
        d["nickname"] = auth
        d["imageURL"] = profURL
        session_collection.insert_one(d)
    auth_mess = {
            "author":auth,
            "id":str(uuid.uuid4()),
            "content": con,
            "updated":False
        }
    chat_collection.insert_one(auth_mess)
    res.set_status(200,"OK") 
    res.text("pass")
    handler.request.sendall(res.to_data())

def deleteC(request, handler):
    res = Response()
    messageid = request.path.split("/")[-1]
    if "auth_token" in request.cookies:
        d = {}
        d["id"] = messageid
        chat = chat_collection.find_one(d)
        if chat is None:
            res.set_status(404,"Not Found")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
        auth_token = request.cookies["auth_token"]
        hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
        i = {}
        i["auth_token"] = hash_auth
        userID = userAuth_collection.find_one(i).get("id")
        filter = {}
        filter["id"] = userID
        auth = userPass_collection.find_one(filter).get("username")

        if auth is not None:
            if (auth) == chat["author"]:
                chat_collection.delete_one(d)
                res.set_status(200,"OK")
                res.text("pass")
                handler.request.sendall(res.to_data())
                return
            else:
                res.set_status(403,"Forbidden")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
        else:
            res.set_status(404,"Not Found")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
    elif "session" in request.cookies:
        d = {}
        d["id"] = messageid
        chat = chat_collection.find_one(d)
        if chat is None:
            res.set_status(404,"Not Found")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
        if (request.cookies["session"]) == chat["author"]:
            chat_collection.delete_one(d)
            res.set_status(200,"OK")
            res.text("pass")
            handler.request.sendall(res.to_data())
            return
        else:
            res.set_status(403,"Forbidden")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
    else:
        res.set_status(403,"Forbidden")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

def patchC(request, handler):
    res = Response()
    messageid = request.path.split("/")[-1]
    if "auth_token" in request.cookies:
        c = {}
        data = json.loads(request.body.decode("utf-8"))
        con = escapeContents(data.get("content"))
        c["content"] = con
        c["updated"] = True
        d = {}
        d["id"] = messageid
        chat = chat_collection.find_one(d)
        if chat is None:
            res.set_status(404,"Not Found")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
        auth_token = request.cookies["auth_token"]
        hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
        i = {}
        i["auth_token"] = hash_auth
        userID = userAuth_collection.find_one(i).get("id")
        filter = {}
        filter["id"] = userID
        auth = userPass_collection.find_one(filter).get("username")
        if auth is not None:
            if (auth) == chat["author"]:
                chat_collection.update_one(d,{"$set":c})
                res.set_status(200,"OK")
                res.text("pass")
                handler.request.sendall(res.to_data())
                return
            else:
                res.set_status(403,"Forbidden")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
        else:
            res.set_status(404,"Not Found")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
    elif "session" in request.cookies:
        c = {}
        data = json.loads(request.body.decode("utf-8"))
        con = escapeContents(data.get("content"))
        c["content"] = con
        c["updated"] = True
        d = {}
        d["id"] = messageid
        chat = chat_collection.find_one(d)
        if chat is None:
            res.set_status(404,"Not Found")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
        if (request.cookies["session"]) == chat["author"]:
            chat_collection.update_one(d,{"$set":c})
            res.set_status(200,"OK")
            res.text("pass")
            handler.request.sendall(res.to_data())
            return
        else:
            res.set_status(403,"Forbidden")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
    else:
        res.set_status(403,"Forbidden")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    
def nicknamePatch(request, handler):
    res = Response()
    if "auth_token" in request.cookies:
        auth_token = request.cookies["auth_token"]
        hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
        i = {}
        i["auth_token"] = hash_auth
        userID = userAuth_collection.find_one(i).get("username")
        filter = {}
        filter["id"] = userID
        auth = userPass_collection.find_one(filter).get("username")
        if auth is not None:
            c = {}
            d = {}
            data = json.loads(request.body.decode("utf-8"))
            new_nickname = escapeContents(data.get("nickname"))
            c["nickname"] = new_nickname
            c["author"] = auth
            d["author"] = auth
            if new_nickname:
                session_collection.update_one(d,{"$set":c}, upsert = True)
                res.set_status(200,"OK")
                res.text("pass")
                handler.request.sendall(res.to_data())
                return
                
            else:
                res.set_status(400,"Bad Request")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
        else:
            res.set_status(404,"Not Found")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
    elif "session" in request.cookies:
        c = {}
        d = {}
        data = json.loads(request.body.decode("utf-8"))
        new_nickname = escapeContents(data.get("nickname"))
        c["nickname"] = new_nickname
        c["author"] = request.cookies["session"]
        d["author"] = request.cookies["session"]

        if new_nickname:
            session_collection.update_one(d,{"$set":c}, upsert = True)
            res.set_status(200,"OK")
            res.text("pass")
            handler.request.sendall(res.to_data())
            return
            
        else:
            res.set_status(400,"Bad Request")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
    else:
        res.set_status(403,"Forbidden")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

def patchR(request, handler):
    res = Response()
    messageid = request.path.split("/")[-1]
    if "auth_token" in request.cookies:
        data = json.loads(request.body.decode("utf-8"))
        emoji = escapeContents(data.get("emoji"))
        if emoji:
            d = {}
            d["id"] = messageid
            chat = chat_collection.find_one(d)
            if chat is None:
                res.set_status(404,"Not Found")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
            auth_token = request.cookies["auth_token"]
            hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
            i = {}
            i["auth_token"] = hash_auth
            userID = userAuth_collection.find_one(i).get("username")
            filter = {}
            filter["id"] = userID
            auth = userPass_collection.find_one(filter).get("username")
            if auth is not None:  
                c = {}
                c["reactions"] = emoji
                c["author"] = auth
                c["id"] = messageid
                react = reaction_collection.find_one(c)
            else:
                res.set_status(404,"Not Found")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
            if react is None:
                reaction_collection.insert_one(c)
                res.set_status(200,"OK")
                res.text("pass")
                handler.request.sendall(res.to_data())
                return

            else:
                res.set_status(403,"Forbidden")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
    if "session" in request.cookies:
        data = json.loads(request.body.decode("utf-8"))
        emoji = escapeContents(data.get("emoji"))
        if emoji:
            d = {}
            d["id"] = messageid
            chat = chat_collection.find_one(d)
            if chat is None:
                res.set_status(404,"Not Found")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
            c = {}
            c["reactions"] = emoji
            c["author"] = request.cookies["session"]
            c["id"] = messageid
            react = reaction_collection.find_one(c)
            
            if react is None:
                reaction_collection.insert_one(c)
                res.set_status(200,"OK")
                res.text("pass")
                handler.request.sendall(res.to_data())
                return

            else:
                res.set_status(403,"Forbidden")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
    else:
        res.set_status(403,"Forbidden")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

def deleteR(request, handler):
    res = Response()
    messageid = request.path.split("/")[-1]
    if "auth_token" in request.cookies:
        data = json.loads(request.body.decode("utf-8"))
        emoji = escapeContents(data.get("emoji"))
        if emoji:
            d = {}
            d["id"] = messageid
            chat = chat_collection.find_one(d)
            if chat is None:
                res.set_status(404,"Not Found")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
            auth_token = request.cookies["auth_token"]
            hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
            i = {}
            i["auth_token"] = hash_auth
            userID = userAuth_collection.find_one(i).get("id")
            filter = {}
            filter["id"] = userID
            auth = userPass_collection.find_one(filter).get("username")
            if auth is not None:  
                c = {}
                c["reactions"] = emoji
                c["author"] = auth
                c["id"] = messageid
                react = reaction_collection.find_one(c)
                if react is not None:
                    reaction_collection.delete_one(c)
                    res.set_status(200,"OK")
                    res.text("pass")
                    handler.request.sendall(res.to_data())
                    return
                else:
                    res.set_status(403,"Forbidden")
                    res.text("failed")
                    handler.request.sendall(res.to_data())
                    return
            else:
                res.set_status(404,"Not Found")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
    if "session" in request.cookies:
        data = json.loads(request.body.decode("utf-8"))
        emoji = escapeContents(data.get("emoji"))
        if emoji:
            d = {}
            d["id"] = messageid
            chat = chat_collection.find_one(d)
            if chat is None:
                res.set_status(404,"Not Found")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
            c = {}
            c["reactions"] = emoji
            c["author"] = request.cookies["session"]
            c["id"] = messageid
            react = reaction_collection.find_one(c)
            if react is not None:
                reaction_collection.delete_one(c)
                res.set_status(200,"OK")
                res.text("pass")
                handler.request.sendall(res.to_data())
                return
            else:
                res.set_status(403,"Forbidden")
                res.text("failed")
                handler.request.sendall(res.to_data())
                return
    else:
        res.set_status(403,"Forbidden")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

def register(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/register.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def getLog(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/login.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def settings(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/settings.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def search(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/search-users.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def registration(request,handler):
    res = Response()
    user_info = extract_credentials(request)
    password = user_info[1]
    user = user_info[0]
    valid = validate_password(password)
    if not valid:
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

    usernames = {}
    usernames["username"] = user
    check = userPass_collection.find_one(usernames)
    if check is not None:
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    
    profile_pic = requests.get("https://api.dicebear.com/9.x/thumbs/svg?seed=" + str(uuid.uuid4()))
    profURL = "public/imgs/profile-pics/" + str(uuid.uuid4()) + ".svg"
    with open(profURL, "wb") as file:
        file.write(profile_pic.content)
    d = {}
    d["author"] = user
    d["nickname"] = user
    d["imageURL"] = profURL
    session_collection.insert_one(d)

    user_pass = {}
    user_pass["password"] = bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode("utf-8")
    user_pass["username"] = user
    user_pass["id"] = str(uuid.uuid4())
    userPass_collection.insert_one(user_pass)
    res.set_status(200,"OK")
    res.text("pass")
    handler.request.sendall(res.to_data())
    return

def postLog(request, handler):
    res = Response()
    body = request.body
    if body is None:
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

    user_info = extract_credentials(request)
    password = user_info[1]
    user = user_info[0]
    username = {}
    username["username"] = user
    check_user = userPass_collection.find_one(username)
    if check_user is None:
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    
    encrypt_pass = check_user.get("password")
    check_pass = bcrypt.checkpw(password = password.encode(), hashed_password = encrypt_pass.encode())
    if not check_pass:
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    
    cookie={}
    auth_token = str(uuid.uuid4())
    cookie["auth_token"] = auth_token + ";Max-Age=99999999999;HttpOnly" 
    res.cookies(cookie)
    userID = check_user.get("id")
    hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
    auth = {}
    auth["auth_token"] = hash_auth
    auth["id"] = userID
    userAuth_collection.insert_one(auth)

    if "session" in request.cookies:
        b = {}
        b["author"] = user
        c = {}
        c["author"] = request.cookies["session"]
        chat_collection.update_many(c,{"$set":b})

    res.set_status(200,"OK")
    res.text("pass")
    handler.request.sendall(res.to_data())
    return

def logout(request, handler):
    res = Response()
    auth = request.cookies["auth_token"]
    hash_auth = hashlib.sha256(auth.encode()).hexdigest()
    i = {}
    i["auth_token"] = hash_auth
    check = userAuth_collection.find_one(i)
    if check is not None:
        userAuth_collection.delete_one(i)
        cookie={}
        auth_token = ""
        cookie["auth_token"] = auth_token + ";Max-Age=0;HttpOnly" 
        res.cookies(cookie)
        res.set_status(200,"OK")
        res.text("pass")
        handler.request.sendall(res.to_data())
        return
    else:
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

def me(request, handler):
    res = Response()
    if "auth_token" in request.cookies:
        auth = request.cookies["auth_token"]
        hash_auth = hashlib.sha256(auth.encode()).hexdigest()
        i = {}
        i["auth_token"] = hash_auth
        check = userAuth_collection.find_one(i)
        d = {}
        if check is not None:
            userID = check.get("id")
            filter = {}
            filter["id"] = userID
            find_user = userPass_collection.find_one(filter)
            if find_user is not None:
                user= find_user.get("username")
                s = {}
                s["author"] = user
                profile = session_collection.find_one(s)
                if profile is not None:
                    check_prof = profile.get("imageURL")
                    if check_prof is not None:
                        d["imageURL"] = check_prof
                        d["id"] = userID
                        d["username"] = user
                        res.set_status(200,"OK")
                        res.text("pass")
                        res.json(d)
                        handler.request.sendall(res.to_data())
                        return 
                    else:
                        d["id"] = userID
                        d["username"] = user
                        res.set_status(200,"OK")
                        res.text("pass")
                        res.json(d)
                        handler.request.sendall(res.to_data())
                        return 
                else:
                    d["id"] = userID
                    d["username"] = user
                    res.set_status(200,"OK")
                    res.text("pass")
                    res.json(d)
                    handler.request.sendall(res.to_data())
                    return
            else:
                d["username"] = ""
                d["id"] = ""
                res.set_status(401,"Unauthorized")
                res.text("failed")
                res.json(d)
                handler.request.sendall(res.to_data())
                return
        else:
            d["username"] = ""
            d["id"] = ""
            res.set_status(401,"Unauthorized")
            res.text("failed")
            res.json(d)
            handler.request.sendall(res.to_data())
            return
    else:
        d = {}
        d["username"] = ""
        d["id"] = ""
        res.set_status(401,"Unauthorized")
        res.text("failed")
        res.json(d)
        handler.request.sendall(res.to_data())
        return 
    
def userSearch(request, handler):
    res = Response()
    querySearch = request.path.split("?")[-1]
    searchUser = querySearch.split("=")[-1]
    if len(searchUser) == 0:
        result = {}
        result["users"] = []
        res.json(result)
        res.set_status(200,"OK")
        res.text("pass")
        handler.request.sendall(res.to_data())
        return
    test = list(userPass_collection.find({"username":{"$regex":f"{searchUser}", "$options": ""}},{"_id": 0, "id": 1, "username": 1}))
    result = {}
    result["users"] = test
    res.set_status(200,"OK")
    res.text("pass")
    res.json(result)
    handler.request.sendall(res.to_data())
    return 

def postSetting(request, handler):
    res = Response()
    body = request.body
    if body is None:
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

    user_info = extract_credentials(request)
    given_password = user_info[1]
    given_user = user_info[0]

    if "auth_token" in request.cookies:
        auth_token = request.cookies["auth_token"]
        hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
        i = {}
        i["auth_token"] = hash_auth
        userID = userAuth_collection.find_one(i).get("id")
        user = {}
        user["id"] = userID

        get_userID = userPass_collection.find_one(user)
        if get_userID is None:
            res.set_status(400,"Bad Request")
            res.text("failed")
            handler.request.sendall(res.to_data())
            return
    
    get_pass = get_userID.get("password")
    get_user = get_userID.get("username")
    check_pass = bcrypt.checkpw(given_password.encode(), get_pass.encode())
    if len(given_password) == 0:
        b = {}
        b["username"] = given_user
        c = {}
        c["username"] = get_user
        userPass_collection.update_one(c,{"$set":b})

        res.set_status(200,"OK")
        res.text("pass")
        handler.request.sendall(res.to_data())
        return
    valid = validate_password(given_password)
    if not valid:       
        res.set_status(400,"Bad Request")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    elif ((not check_pass) or (given_user != get_user)) :
        b = {}
        b["username"] = given_user
        b["password"] = bcrypt.hashpw(given_password.encode(),bcrypt.gensalt()).decode("utf-8")
        c = {}
        c["username"] = get_user
        c["password"] = get_pass
        userPass_collection.update_one(c,{"$set":b})

    res.set_status(200,"OK")
    res.text("pass")
    handler.request.sendall(res.to_data())
    return

def authGit(request, handler):
    res = Response()
    load_dotenv()
    clientID = os.getenv("GIT_CLIENT_ID")
    redirectURI = os.getenv("REDIRECT_URI")
    global state 
    state = str(uuid.uuid4())
    queryString = ("https://github.com/login/oauth/authorize" 
        "?client_id=" + clientID +
        "&redirect_uri=" + redirectURI +
        "&scopes=read:user user:email" 
        "&response_type=code"
        "&state=" + state)
    res.set_status(302,"Redirecting")
    res.headers({"Location":queryString})
    handler.request.sendall(res.to_data())
    return

def authCallback(request, handler):
    res = Response()
    global state
    clientID = os.getenv("GIT_CLIENT_ID")
    clientSecret = os.getenv("GIT_CLIENT_SECRET")
    redirectURI = os.getenv("REDIRECT_URI")
    codeState = request.path.split("&")
    stateValue = codeState[1].split("=")[1]
    codeValue = codeState[0].split("=")[1]
    res.set_status(302,"Redirecting")
    if (state == stateValue):
        state = ""
        queryString = ("https://github.com/login/oauth/access_token"
        "?client_id=" + clientID +
        "&client_secret=" + clientSecret +
        "&code=" + codeValue +
        "&redirect_uri=" + redirectURI +
        "&grant_type=authorization_code")
        psot = requests.post(queryString).text
        aToken = psot.split("&")[0].split("=")[1]
        d = {}
        d["Content-Type"] = "application/json"
        d["Authorization"] = "Bearer " + str(aToken)
        info = requests.get("https://api.github.com/user", headers = d).text
        userID = str(info['id'])
        auth_token = str(uuid.uuid4())
        c = {}
        c["id"] = userID
        check = userPass_collection.find_one(c)
        if check is None:
            user_pass = {}
            user_pass["git_token"] = aToken
            user_pass["username"] = info['login']
            user_pass["id"] = userID
            userPass_collection.insert_one(user_pass)
            hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
            token = {}
            token["auth_token"] = hash_auth
            token["id"] = userID
            userAuth_collection.insert_one(token)
        else:
            hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
            uID = {}
            uID["id"] = userID
            auth = {}
            auth["auth_token"] = hash_auth
            userAuth_collection.update_one(uID, {"$set": auth})
        res.headers({"Location": "/"})
        res.cookies({"auth_token":auth_token})
    else:
        res.set_status(401,"Unauthorized")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return

    handler.request.sendall(res.to_data())
    return

def avatar(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/change-avatar.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def vtube(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/videotube.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def vtubeUp(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/upload.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def vtubeVid(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/view-video.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())
            
def avatar_change(request, handler):
    res = Response()
    parse = parse_multipart(request)
    spliting = parse.parts[0].headers["Content-Disposition"].split(".")[1].replace('"','')
    mtype = "." + spliting
    profilePic = "public/imgs/profile-pics/" + str(uuid.uuid4()) + mtype
    with open(profilePic, "wb") as file:
        file.write(parse.parts[0].content)

    user = request.cookies["auth_token"]
    hash_auth = hashlib.sha256(user.encode()).hexdigest()
    i = {}
    i["auth_token"] = hash_auth
    userID = userAuth_collection.find_one(i)
    if userID is None:
        res.set_status(404,"Not Found")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    userID = userID.get("id")
    filter = {}
    filter["id"] = userID
    auth = userPass_collection.find_one(filter)
    if auth is None:
        res.set_status(404,"Not Found")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    auth = auth.get("username")
    s = {}
    s["author"] = auth
    '''checkSess = session_collection.find_one(s)
    if checkSess is None:
        c = {}
        c["nickname"] = auth
        c["author"] = auth
        c["imageURL"] = profilePic
        session_collection.insert_one(c)'''
    f = {}
    f["imageURL"] = profilePic
    session_collection.update_one(s,{"$set":f})

    res.set_status(200,"OK")
    res.text("pass")
    handler.request.sendall(res.to_data())
    return

def postVideo(request, handler):
    res = Response()
    user = request.cookies["auth_token"]
    hash_auth = hashlib.sha256(user.encode()).hexdigest()
    i = {}
    i["auth_token"] = hash_auth
    userID = userAuth_collection.find_one(i)
    if userID is None:
        res.set_status(404,"Not Found")
        res.text("failed")
        handler.request.sendall(res.to_data())
        return
    userID = userID.get("id")
    parse = parse_multipart(request)
    title = parse.parts[0].content.replace(b"\r\n", b"").decode()
    description = parse.parts[1].content.replace(b"\r\n", b"").decode()
    video = parse.parts[2].content
    videoID = str(uuid.uuid4())
    videoURL = "public/videos/" + videoID + ".mp4"

    with open(videoURL, "wb") as file:
        file.write(video)

    items = {}
    items["author_id"] = userID
    items["title"] = str(title)
    items["description"] = str(description)
    items["video_path"] = videoURL
    items["created_at"] = datetime.datetime.now()
    items["id"] = videoID
    video_collection.insert_one(items)

    d = {}
    d["id"] = videoID
    res.set_status(200,"OK")
    res.text("pass")
    res.json(d)
    handler.request.sendall(res.to_data())
    return

def getAllVideo(request, handler):
    res = Response()
    vid = []
    coll = video_collection.find()
    for item in coll:
        items = {}
        items["author_id"] = item["author_id"]
        items["title"] = item["title"]
        items["description"] = item["description"]
        items["video_path"] = item["video_path"]
        items["created_at"] = str(item["created_at"])
        items["id"] = item["id"]
        vid.append(items)
    d = {}
    d["videos"] = vid
    res.set_status(200,"OK")
    res.text("pass")
    res.json(d)
    handler.request.sendall(res.to_data())
    return

def getSingleVideo(request, handler):
    res = Response()
    videoID = request.path.split("/")[-1]
    d = {}
    d["id"] = videoID
    coll = video_collection.find_one(d)
    items = {}
    if coll is not None:
        items["author_id"] = coll["author_id"]
        items["title"] = coll["title"]
        items["description"] = coll["description"]
        items["video_path"] = coll["video_path"]
        items["created_at"] = str(coll["created_at"])
        items["id"] = coll["id"]
    a = {}
    a["video"] = items
    res.set_status(200,"OK")
    res.text("pass")
    res.json(a)
    handler.request.sendall(res.to_data())
    return

def websocket_page(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/test-websocket.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def drawing_page(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/drawing-board.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def message_page(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/direct-messaging.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def video_page(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/video-call.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

def videoroom_page(request, handler):
    with open("public/layout/layout.html","r") as layout:
        layoutF = layout.read()
        with open("public/video-call-room.html","r") as index:
            indexF = index.read()
            page=layoutF.replace("{{content}}", indexF)
            res = Response()
            res.text(page)
            head={}
            head["Content-Type"] = "text/html; charset=utf-8"
            head["X-Content-Type-Options"] = "nosniff"
            res.headers(head)
            handler.request.sendall(res.to_data())

connectionDict = {}
def websocket_handshake(request, handler):
    res = Response()
    auth_token = request.cookies["auth_token"]
    hash_auth = hashlib.sha256(auth_token.encode()).hexdigest()
    i = {}
    i["auth_token"] = hash_auth
    userID = userAuth_collection.find_one(i).get("id")
    filter = {}
    filter["id"] = userID
    auth = userPass_collection.find_one(filter).get("username")
    connectionDict[auth] = handler
    webSocketKey = request.headers["Sec-WebSocket-Key"]
    res.set_status(101,"Switching Protocols")
    d = {}
    d["Upgrade"] = "websocket"
    d["Connection"] = "Upgrade"
    d["Sec-WebSocket-Accept"] = compute_accept(webSocketKey)

    res.headers(d)
    handler.request.sendall(res.to_data())
    
    #init starts
    frames = drawing_collection.find()
    frameData = []
    for item in frames:
        t = {}
        t["startX"] = item["startX"]
        t["startY"] = item["startY"]
        t["endX"] = item["endX"]
        t["endY"] = item["endY"]
        t["color"] = item["color"]
        frameData.append(t)
    s = {}
    s["messageType"]="init_strokes"
    s["strokes"] = frameData
    jencoded = json.dumps(s).encode("utf-8")
    generated = generate_ws_frame(jencoded)
    for user in connectionDict:
        connectionDict[user].request.sendall(generated)
    #init ends

    userlist = []
    for u in connectionDict:
        p = {}
        p["username"] = u
        userlist.append(p)
    mess = {}
    mess["messageType"] = "active_users_list"
    mess["users"] = userlist
    jencoded = json.dumps(mess).encode("utf-8")
    generated = generate_ws_frame(jencoded)
    for user in connectionDict:
        connectionDict[user].request.sendall(generated)

    while True:
        data = handler.request.recv(2048)
        payload = parse_ws_frame(data).payload
        payloadLen = parse_ws_frame(data).payload_length
        actualLen = len(payload)
        message = data

        while (payloadLen != actualLen):
            data = handler.request.recv(2048)
            actualLen += len(data)
            message += data

        parseMessage = parse_ws_frame(message)

        if (parseMessage.opcode == 8):
            connectionDict.pop(auth)
            userlist = []
            for u in connectionDict:
                p = {}
                p["username"] = u
                userlist.append(p)
            mess = {}
            mess["messageType"] = "active_users_list"
            mess["users"] = userlist
            jencoded = json.dumps(mess).encode("utf-8")
            generated = generate_ws_frame(jencoded)
            for user in connectionDict:
                connectionDict[user].request.sendall(generated)
            break
        getting_payload = parseMessage.payload
        payload = json.loads(getting_payload.decode())
        messageType = payload["messageType"]

        if (messageType == "echo_client"):
            message = payload["text"]
            send = {}
            send["messageType"] = "echo_server"
            send["text"] = message
            
            jencoded = json.dumps(send).encode("utf-8")
            generated = generate_ws_frame(jencoded)
            handler.request.sendall(generated)
        elif(messageType == "drawing"):
            jencoded = json.dumps(payload).encode("utf-8")
            generated = generate_ws_frame(jencoded)
            for user in connectionDict:
                connectionDict[user].request.sendall(generated)
            drawing_collection.insert_one(payload)
