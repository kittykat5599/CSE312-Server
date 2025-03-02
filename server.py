import socketserver
from util.request import Request
from util.router import Router
from util.hello_path import hello_path, home, chat, public, postC, getC, patchC, deleteC, nicknamePatch, patchR, deleteR, register, getLog, settings, search, registration, logout, postLog, me, postSetting, userSearch


class MyTCPHandler(socketserver.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        self.router = Router()
        self.router.add_route("GET", "/hello", hello_path, True)
        # TODO: Add your routes here
        self.router.add_route("GET", "/public", public, False)
        self.router.add_route("GET", "/", home, True)
        self.router.add_route("GET", "/chat", chat, True)
        self.router.add_route("POST", "/api/chats", postC, True)
        self.router.add_route("GET", "/api/chats", getC, True)
        self.router.add_route("PATCH", "/api/chats/", patchC, False)
        self.router.add_route("DELETE", "/api/chats/", deleteC, False)
        
        self.router.add_route("PATCH", "/api/reaction/", patchR, False)
        self.router.add_route("DELETE", "/api/reaction/", deleteR, False)

        self.router.add_route("PATCH", "/api/nickname", nicknamePatch, True)

        self.router.add_route("GET", "/register", register, True)
        self.router.add_route("GET", "/login", getLog, True)
        self.router.add_route("GET", "/settings", settings, True)
        self.router.add_route("GET", "/search-users", search, True)

        self.router.add_route("POST", "/register", registration, True)
        self.router.add_route("POST", "/login", postLog, True)
        self.router.add_route("GET", "/logout", logout, True)

        self.router.add_route("GET", "/api/users/@me", me, True)
        self.router.add_route("GET", "/api/users/search", userSearch, False)

        self.router.add_route("POST", "/api/users/settings", postSetting, True)





        super().__init__(request, client_address, server)

    def handle(self):
        received_data = self.request.recv(2048)
        print(self.client_address)
        print("--- received data ---")
        print(received_data)
        print("--- end of data ---\n\n")
        request = Request(received_data)

        self.router.route_request(request, self)


def main():
    host = "0.0.0.0"
    port = 8080
    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.TCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    server.serve_forever()


if __name__ == "__main__":
    main()
