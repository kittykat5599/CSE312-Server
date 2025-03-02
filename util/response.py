import json

class Response:
    def __init__(self):
        self.status_code = 200
        self.status_text = "OK"
        self.header = {}
        self.cookie = {}
        self.body = b""


    def set_status(self, code, text):
        self.status_code = code
        self.status_text = text
        return self

    def headers(self, headers):
        for key, value in headers.items():
            self.header[key] = value
        return self

    def cookies(self, cookies):
        for key, value in cookies.items():
            self.cookie[key] = value + "; Path=/"
        return self

    def bytes(self, data):
        self.body += data
        return self

    def text(self, data):
        self.body += data.encode()
        return self

    def json(self, data):
        self.body = json.dumps(data).encode()
        self.header["Content-Type"] = "application/json"
        return self

    def to_data(self):
        # Default content type if not already set
        if "Content-Type" not in self.header:
            self.header["Content-Type"] = "text/plain; charset=utf-8"

        # Ensure content length header is set
        self.header["Content-Length"] = str(len(self.body))
        
        #nosniff
        self.header["X-Content-Type-Options"] = "nosniff"

        

        # Construct response headers
        response_headers = [f"HTTP/1.1 {self.status_code} {self.status_text}"]
        for key, value in self.header.items():
            response_headers.append(f"{key}: {value}")
        for key, value in self.cookie.items():
            response_headers.append(f"Set-Cookie:{key}={value}")
        
        # Combine headers and body
        response = "\r\n".join(response_headers).encode() + b"\r\n\r\n" + self.body
        return response

def test1():
    res = Response()
    res.text("hello")
    expected = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello'
    actual = res.to_data()
    assert actual == expected

if __name__ == '__main__':
    test1()