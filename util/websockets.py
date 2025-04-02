import hashlib
import base64

def compute_accept(WebKey):
    #get key
    #hash key + GUID
    #convert hash to Askii
    #base64 encode the covertedd hash
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    source = WebKey + GUID
    hashSha1 = hashlib.sha1(source.encode()).digest()
    acceptKey = base64.b64encode(hashSha1).decode()
    return acceptKey

class WebSocketFrame:
    def __init__(self, fin_bit, opcode, payload_length, payload):
        self.fin_bit = fin_bit
        self.opcode = opcode
        self.payload_length = payload_length
        self.payload = payload

def parse_ws_frame(WebsocketBytes):
    fin_bit = (WebsocketBytes[0] >> 7) & 1
    opcode = WebsocketBytes[0] & 0x0F
    mask_bit = (WebsocketBytes[1] >> 7) & 1
    payload_len = WebsocketBytes[1] & 0x7F
    index = 2
    
    if payload_len == 126:
        payload_length = int.from_bytes(WebsocketBytes[index:index + 2], 'big')
        index += 2
    elif payload_len == 127:
        payload_length = int.from_bytes(WebsocketBytes[index:index + 8], 'big')
        index += 8
    else:
        payload_length = payload_len
    
    if mask_bit:
        mask_key = WebsocketBytes[index:index + 4]
        index += 4
    else:
        mask_key = None
    
    payload = WebsocketBytes[index:index + payload_length]
    
    if mask_bit and mask_key:
        unmasked_payload = []
        for i, b in enumerate(payload):
            part = b ^ mask_key[i % 4]
            unmasked_payload.append(part)
        payload = bytes(unmasked_payload)
    
    return WebSocketFrame(fin_bit, opcode, payload_length, payload)

def generate_ws_frame(WebsocketBytes):
    fin_bit = 1
    opcode = 0x1 
    first_byte = fin_bit * 128 + opcode
    payload_length = len(WebsocketBytes)
    
    if payload_length <= 125:
        second_byte = payload_length
        header = bytes([first_byte, second_byte])
    elif payload_length <= 65535:
        second_byte = 126
        header = bytes([first_byte, second_byte]) + payload_length.to_bytes(2, 'big')
    else:
        second_byte = 127
        header = bytes([first_byte, second_byte]) + payload_length.to_bytes(8, 'big')
    
    frame = header + WebsocketBytes
    return frame

def test1():
    key = "MXYIMtVbjLyreuG0Q1q3wg=="
    expected = "5r3mRvWZxmTQ64GVf03iCXKTmMc="
    actual = compute_accept(key) 
    print(expected)
    print(actual)   
    assert expected == actual
    

if __name__ == '__main__':
    test1()

