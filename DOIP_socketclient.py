import socket
import ssl

fn = "DOIPrequests/Hello_Request.doip"
inData = ''
with open(fn) as fin:
    for line in fin:
        inData += line

# for wrong targetId use:
# inData = '{\n  "targetId": "20.500.124/service",\n  "operationId": "0.DOIP/Op.Hello"\n}\n#\n#\n'

server_port = 8443
server_addr = 'localhost'
ctx = ssl.create_default_context()
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.check_hostname = True
ctx.load_verify_locations("certs/server.crt")
ctx.load_cert_chain(certfile="certs/client1.crt", keyfile="certs/client1.key")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    with ctx.wrap_socket(sock, server_hostname=server_addr) as ssl_sock:
        ssl_sock.connect((server_addr, server_port))
        ssl_sock.sendall(bytes(inData, "utf-8"))

        data = ssl_sock.read()
        print (data)
        
