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
    data = data.replace("%3A", ":")
    data = data.replace("%2F", "/")
    data = data.replace("%3F", "?")
    data = data.replace("%5B", "[")
    data = data.replace("%5D", "]")
    data = data.replace("%27", "'")
    data = data.replace("%2A", "*")
    data = data.replace("%2B", "+")
    data = data.replace("%2C", ",")
    data = data.replace("%3B", ";")
    data = data.replace("%20", " ")
    data = data.replace("%3C", "<")
    data = data.replace("%3E", ">")
    data = data.replace("%60", "`")
    data = data.replace("%7B", "{")
    data = data.replace("%7C", "|")
    data = data.replace("%7D", "}")
    data = data.replace("%7E", "~")
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


def test1():
    password = "Kl123!"
    assert validate_password(password) == False
def test8():
    password = "Kl12378!"
    assert validate_password(password) == False
def test2():
    password = "Kl123456789"
    assert validate_password(password) == False
def test3():    
    password = "Klasdfsdfasdfs!"
    assert validate_password(password) == False
def test4():    
    password = "Kl123456<!"
    assert validate_password(password) == False
def test5():    
    password = "KLAJKSLKAJD123!"
    assert validate_password(password) == False
def test6():    
    password = "asdasddasdal123!"
    assert validate_password(password) == False
def test7():    
    password = "Kl123456!"
    assert validate_password(password) == True

if __name__ == '__main__':
    test1()
    test2()
    test3()
    test4()
    test5()
    test6()
    test7()
