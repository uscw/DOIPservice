import socket
import ssl
import json

import DOIPio

fn = "DOIPrequests/Hello_Request.doip"
inData = ''
with open(fn) as fin:
    for line in fin:
        inData += line
print("retrieving request from:", fn)

class DOIPServerConfig():

    def __init__(self):
        self.service_ids = ["0.DOIP/Op.Hello@20.500.123/service", "0.DOIP/Op.Create@20.500.123/service", "0.DOIP/Op.Retrieve@20.500.123/service", "0.DOIP/Op.Update@20.500.123/service", "0.DOIP/Op.Delete@20.500.123/service", "0.DOIP/Op.Search@20.500.123/service", "0.DOIP/Op.ListOperations@20.500.123/service"]
        self.listen_addr = 'localhost'
        self.listen_port = 8443
        self.server_cert = 'certs/server.crt'
        self.client_key = 'certs/client1.key'
        self.client_cert = 'certs/client1.crt'
        self.context_verify_mode = ssl.CERT_REQUIRED


config = DOIPServerConfig()
                 
ctx = ssl.create_default_context()
ctx.verify_mode = config.context_verify_mode
ctx.check_hostname = True
ctx.load_verify_locations(config.server_cert)
ctx.load_cert_chain(certfile=config.client_cert, keyfile=config.client_key)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    with ctx.wrap_socket(sock, server_hostname=config.listen_addr) as ssl_sock:
        ssl_sock.connect((config.listen_addr, config.listen_port))
        
        ssl_sock.sendall(bytes(inData, "utf-8"))
        rfile = ssl_sock.makefile('rb', 1024)
        DOIPRequest = DOIPio.InputMessageProcessing(ssl_sock,rfile,config)
        # now listen to server
        segment_1st = DOIPRequest.getLeadingSegment()
        janswer = DOIPRequest._segment_to_json(segment_1st)
        print (json.dumps(janswer, sort_keys=True,indent=2, separators=(',', ' : ')))

        
fn = "DOIPrequests/ListOperations_Request.doip"
print("retrieving request from:", fn)
inData = ''
with open(fn) as fin:
    for line in fin:
        inData += line

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    with ctx.wrap_socket(sock, server_hostname=config.listen_addr) as ssl_sock:
        ssl_sock.connect((config.listen_addr, config.listen_port))
        ssl_sock.sendall(bytes(inData, "utf-8"))
        rfile = ssl_sock.makefile('rb', 1024)
        DOIPRequest = DOIPio.InputMessageProcessing(ssl_sock,rfile,config)
        # now listen to server
        segment_1st = DOIPRequest.getLeadingSegment()
        janswer = DOIPRequest._segment_to_json(segment_1st)
        print (json.dumps(janswer, sort_keys=True,indent=2, separators=(',', ' : ')))
        
