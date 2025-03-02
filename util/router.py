from util.response import Response
class Router:

    def __init__(self):
        self.routes = []

    def add_route(self, method, path, action, exact_path=False):
        self.routes.append({"method": method, "path": path, "action": action, "exact_path": exact_path})
   

    def route_request(self, request, handler):
        match = None
        for route in self.routes:
            #check if methods match
            if route["method"] != request.method:
                continue
            #check if path matches
            if route["exact_path"]:
                if route["path"] == request.path:
                    match = route
                    break
            else:
                if request.path.startswith(route["path"]):
                    match = route
                    break
        if match:
            #call corresponding action
            match["action"](request,handler)
        else:
            # no route found send 404\
            res = Response()
            res.set_status(404, "Not Found")
            handler.request.sendall(res.to_data())

