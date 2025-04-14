"""#ao1 attempt
    msgFragment = b''
    tempOpcode = None
    recvBuffer = b''
    while True:
        data = handler.request.recv(2048)
        recvBuffer += data
        while True:
            #result = parse_ws_frame(recvBuffer)
            fin_bit = parse_ws_frame(recvBuffer).fin_bit
            opcode = parse_ws_frame(recvBuffer).opcode
            recv_payload = parse_ws_frame(recvBuffer).payload
            if (opcode == 0):
                msgFragment += recv_payload
                if fin_bit:
                    fullPayload = msgFragment
                    msgFragment = b''
                    opcode = tempOpcode
                else:
                    continue
            elif (fin_bit == 0):
                tempOpcode = opcode
                msgFragment = recv_payload
                continue
            else:
                fullPayload = recv_payload
            
            if (opcode == 8):
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


            
            payload = json.loads(fullPayload.decode())
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
            
            #ao2
            elif(messageType == "get_all_users"):
                users = []
                all_users = userPass_collection.find()
                for user in all_users:
                    userDict = {}
                    userDict["username"] = user["username"]
                    users.append(userDict)
                response = {}
                response["messageType"] = "all_users_list"
                response["users"] = users
                jencoded = json.dumps(response).encode("utf-8")
                generated = generate_ws_frame(jencoded)
                handler.request.sendall(generated)
            
            elif(messageType == "select_user"):
                target_user = payload["targetUser"]
                filter1 = {}
                filter1["fromUser"] = auth
                filter1["toUser"] = target_user
                filter2 = {}
                filter2["fromUser"] = target_user
                filter2["toUser"] = auth
                orFilters = {}
                orFilters["$or"] = [filter1, filter2]
                dm_mess= directMsg_collection.find(orFilters).sort("sendTime",1)
                messages = list(dm_mess)
                history = []
                for m in messages:
                    messHistory = {}
                    messHistory["messageType"] = "direct_message"
                    messHistory["fromUser"] = m["fromUser"]
                    messHistory["text"] = m["text"]
                    history.append(messHistory)
                response = {}
                response["messageType"] = "message_history"
                response["messages"] = history
                jencoded = json.dumps(response).encode("utf-8")
                generated = generate_ws_frame(jencoded)
                handler.request.sendall(generated)
            
            elif(messageType == "direct_message"):
                toUser = payload["targetUser"]
                text = payload["text"]
                dm_info = {}
                dm_info["fromUser"] = auth
                dm_info["toUser"] = toUser
                dm_info["text"] = text
                dm_info["sendTime"] = datetime.datetime.now(datetime.timezone.utc)
                directMsg_collection.insert_one(dm_info)
                response = {}
                response["messageType"] = "direct_message"
                response["fromUser"] = auth
                response["text"] = text
                jencoded = json.dumps(response).encode("utf-8")
                generated = generate_ws_frame(jencoded)
                if auth in connectionDict:
                    connectionDict[auth].request.sendall(generated)
                if toUser in connectionDict:
                    connectionDict[toUser].request.sendall(generated)


            #ao3
            elif(messageType == "get_calls"):
                calls = list(videoCall_collection.find())
                response = {}
                response["messageType"] = "call_list"
                response["calls"] = calls
                jencoded = json.dumps(response).encode("utf-8")
                generated = generate_ws_frame(jencoded)
                handler.request.sendall(generated)"""