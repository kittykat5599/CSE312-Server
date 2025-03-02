from util.response import Response
import uuid
import json
import requests

def escapeContents(data):
    data = data.replace("&","&amp;")
    data = data.replace("<","&lt;")
    data = data.replace(">","&gt;")
    return data

def specCharReplace(data):
    data = data.replace("%21","!")
    data = data.replace("%40", "@")
    data = data.replace("%23", "#")
    data = data.replace("%24", "$")
    data = data.replace("%5E", "^")
    data = data.replace("%26", "&")
    data = data.replace("%28", "(")
    data = data.replace("%29", ")")
    data = data.replace("%2D", "-")
    data = data.replace("%5F", "_")
    data = data.replace("%3D", "=")
    data = data.replace("%25", "%")
    return data

def extract_credentials(request):
    data = request.body.decode("utf-8")
    split = data.split("&")

    user_pass = {}
    for users in split:
        user_password = users.split("=")
        user_pass[str(user_password[0])] = escapeContents(user_password[1])
    username = user_pass["username"]
    password = specCharReplace(user_pass["password"])
    return [username, password]

def validate_password(password):
    special_char = {'!', '@', '#', '$', '%', '^', '&', '(', ')', '-', '_', '='}
    test_lower = False
    test_upper= False
    test_special = False
    test_digit = False
    test_alnumSpec = True
    if len(password) < 8:
        return False
    for char in password:
        if char.islower():
            test_lower = True
        elif char.isupper():
            test_upper = True
        elif char.isdigit():
            test_digit = True
        elif char in special_char:
            test_special = True
        elif not (char.isalnum() or char in special_char):
            test_alnumSpec = False

    return (test_digit and test_alnumSpec and test_lower and test_special and test_upper)