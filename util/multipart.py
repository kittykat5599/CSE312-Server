class Singlepart:
    def __init__(self, headers, name, content):
        self.headers = headers  
        self.name = name  
        self.content = content  

class Multipart:
    def __init__(self, boundary, parts):
        self.boundary = boundary  
        self.parts = parts

def parse_multipart(request):
    contentType = request.headers["Content-Type"]
    boundaryStart = "boundary="

    boundary = contentType.split(boundaryStart)[-1]
    data = request.body
    dashbound = "--" + boundary
    byte = dashbound.encode("utf-8")
    parts = []
    sections = data.split(byte)[1:-1]

    for section in sections:
        section = section.strip(b"\r\n")
        header_part, content = section.split(b"\r\n\r\n", 1)
        headers = {}
        
        for line in header_part.split(b"\r\n"):
            key, value = line.decode().split(": ", 1)
            headers[key] = value
            if key.lower() == "content-disposition":
                parts_info = value.split("; ")
                for part in parts_info:
                    if part.startswith("name="):
                        name = part.split("=")[1].strip('"')
        parts.append(Singlepart(headers, name, content))
    
    return Multipart(boundary, parts)






'''
exampleInput = (b'POST /test.html HTTP/1.1'
    b'\r\nContent-Type: multipart/form-data; boundary=----geckoformboundaryb70502c12f958badcc424d32d4418fe8'
    b'\r\nContent-Length: 300'
    b'\r\nCookie: auth_token=6ebd369b-42b1-40f1-b3bf-efc6d5a38b2b'
    b'\r\n'
    b'\r\n------geckoformboundaryb70502c12f958badcc424d32d4418fe8'
    b'\r\nContent-Type: text/plain; charset=utf-8'
    b'\r\nContent-Disposition: form-data; name="avatar"; filename="profile pic.png"'
    b'\r\n'
    b'\r\nbody1'
    b'\r\n------geckoformboundaryb70502c12f958badcc424d32d4418fe8'
    b'\r\nContent-Type: application/json'
    b'\r\nContent-Disposition: form-data; name="ava2"'
    b'\r\n'
    b'\r\n{"Title": "Hello"}'
    b'\r\n------geckoformboundaryb70502c12f958badcc424d32d4418fe8'
    b'\r\nContent-Disposition: form-data; name="qq"'
    b'\r\n'
    b'\r\nHello,'
    b'\r\nI am [name]'
    b'\r\n'
    b'\r\nLalalala'
    b'\r\n------geckoformboundaryb70502c12f958badcc424d32d4418fe8--')
    '''