class Request:

    def __init__(self, request: bytes):
        # TODO: parse the bytes of the request and populate the following instance variables
        bodySplit = request.split(b"\r\n\r\n",1)
        #split by "\r\n"
        split = bodySplit[0].decode().split("\r\n")
        method_versionSplit = split[0].split(" ")
        split.pop(0)
        self.body = bodySplit[1]
        self.method = method_versionSplit[0]
        self.path = method_versionSplit[1]
        self.http_version = method_versionSplit[2]
        self.headers = {}
        self.cookies = {}
        for key in split:
            i = key.split(":",1)
            self.headers[i[0]] = i[1].lstrip()
            if i[0] == "Cookie":
                for j in i[1].split(";"):
                    p = j.split("=",1)
                    self.cookies[p[0].strip()] = p[1] 
        
def test1():
    request = Request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n')
    assert request.method == "GET"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b""  # There is no body for this request.
    # When parsing POST requests, the body must be in bytes, not str

    # This is the start of a simple way (ie. no external libraries) to test your code.
    # It's recommended that you complete this test and add others, including at least one
    # test using a POST request. Also, ensure that the types of all values are correct


if __name__ == '__main__':
    test1()
