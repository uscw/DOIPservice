import socketserver
import ssl
import json

class DOIPServerConfig():

    def __init__(self, 
                 listen_addr = '127.0.0.1',
                 listen_port = 8443,
                 server_cert = 'certs/server.crt',
                 server_key = 'certs/server.key',
                 client_cert = 'certs/clients.txt',
                 request_queue_size = 10,
                 daemon_threads = True,
                 allow_reuse_address = True,
                 config_file = None,
                 context_verify_mode = ssl.CERT_OPTIONAL
    ):
        if config_file == None:
            self.listen_addr =         listen_addr
            self.listen_port =         listen_port
            self.server_cert =         server_cert
            self.server_key =          server_key
            self.client_cert =         client_cert
            self.request_queue_size =  request_queue_size
            self.daemon_threads =      daemon_threads
            self.allow_reuse_address = allow_reuse_address
            self.context_verify_mode = context_verify_mode
        else:
            self.read_config_file(config_file)

            
    def read_config_file(self, config_file):
        fd = open(config_file)
        cfg = json.loads(fd.read())
        try:
            self.listen_addr =         cfg["listen_addr"]
            self.listen_port =         cfg["listen_port"]
            self.server_cert =         cfg["server_cert"]
            self.server_key =          cfg["server_key"]
            self.client_cert =         cfg["client_cert"]
            self.request_queue_size =  cfg["request_queue_size"]
            self.daemon_threads =      cfg["daemon_threads"]
            self.allow_reuse_address = cfg["allow_reuse_address"]
            self.context_verify_mode = eval(cfg["context_verify_mode"])
        except:
            print ("Error in Config File: " + config_file + "\n Using the Default" )
        return
        
class Auth_Methods():
    def __init__(self, context, config):
        self.context = context
        self.config = config

    def client_verification_mode(self):

        # require special certs for connection with the following two lines
        # CERT_NONE - no certificates from the other side are required (or will be looked at if provided)
        # CERT_OPTIONAL - certificates are not required, but if provided will be validated, and if validation fails, the connection will also fail
        # CERT_REQUIRED - certificates are required, and will be validated, and if validation fails, the connection will also fail
        self.context.verify_mode = self.config.context_verify_mode # ssl.CERT_OPTIONAL
        # verify source locations, if cert and key are provided by client, cert needs to be known in srv_cfg.client_cert (authorization)
        self.context.load_verify_locations(cafile=self.config.client_cert)

    def get_authentication(self, request_handler, request_cert):
        """
        represents the authentication
        @param request_cert type 
        """
        common_name = None
        try:
            common_name = request_handler._get_certificate_common_name(request_cert)
            print ("common_name:", common_name)          
        except BrokenPipeError:
            print("broken pipe during authentication from {}:{}".format(self.client_address[0], self.client_address[1]))
        return common_name
    
    def get_authorization(self, common_name, service):
        # optionally check client certificate with whitelist, disabled here
        accepted = True
        if service == "ll":
            if (common_name is None or common_name.split("@") != "ulrich"):
                print("rejecting common_name: {}".format(common_name))
                accepted = False
        return accepted

        
class DOIPRequestServer(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, server_address, RequestHandlerClass, srv_cfg, bind_and_activate=True):
        """
        initialize RequestHandler as ThreadingMixIn TCPServer
        setup server context including SSL support
        setup authentication methods and verification mode
        bind the socket and start the server
        @param server_address type tuple: listen address and port of server
        @param RequestHandlerClass type socketserver.RequestHandler: type of RequestHandler
        @param srv_cfg type object: configuration parameters
        @param bind_and_activate type boolean: default True
        """
        self.config = srv_cfg
        # faster re-binding
        allow_reuse_address = srv_cfg.allow_reuse_address
        # make this bigger than five
        request_queue_size = srv_cfg.request_queue_size 
        # kick connections when we exit
        daemon_threads = srv_cfg.daemon_threads
        super().__init__(server_address, RequestHandlerClass, False)

        # setup server context including SSL support
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile=srv_cfg.server_cert, keyfile=srv_cfg.server_key)
        # replace the socket with an ssl version of itself
        self.socket = self.context.wrap_socket(self.socket, server_side=True)
        
        # setup authentication methods and verification mode
        #      self.context.protocol is _SSLMethod.PROTOCOL_TLS
        #      self.config.context_verify_mode is VerifyMode.CERT_OPTIONAL
        #      ...
        self.auth = Auth_Methods(self.context, self.config)
        self.auth.client_verification_mode()
        
        # bind the socket and start the server
        if (bind_and_activate):
            self.server_bind()
            self.server_activate()




class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        """
        supersedes the handle() method in the BaseRequestHandler class of socketserver
        handles requests and answers after authentication and authorization
        """
        print (self.server.config.context_verify_mode)
        print("connection from {}:{}".format(self.client_address[0], self.client_address[1]))

        try:
            request_cert = self.request.getpeercert()
        except BrokenPipeError:
            print("broken pipe from {}:{}".format(self.client_address[0], self.client_address[1]))

        # authentication
        cname = self.server.auth.get_authentication(self,request_cert)

        try:
            # now listen to client
            data = self.rfile.readline().strip()
            #print (">>"+data+"<<")
            print("data: {}".format(data))
            service = self._get_service_from_data(data)
            print (service)
        except BrokenPipeError:
            print("broken pipe from {}:{}".format(self.client_address[0], self.client_address[1]))

        # authorization
        accepted = self.server.auth.get_authorization(cname, service)

        if not accepted:
            self.wfile.write('{"accepted": false}\n'.encode())
        else:
            self.wfile.write('{"accepted": true}\n'.encode())

    def _get_certificate_common_name(self, cert):
        if (cert is None):
            return None

        for sub in cert.get("subject", ()):
            for key, value in sub:
                if (key == "commonName"):
                    return value

    def _get_service_from_data(self, data):
        return data.decode().split()[0]

def main(server_config):
    """
    This is the server. It handles the sockets. It passes requests to the
    listener (the second argument). The server will run in its own thread
    so that we can kill it when we need to.
    bind_and_activate=False can optionally be given in DOIPRequestServer instance
    """
    server = DOIPRequestServer((server_config.listen_addr,
                                server_config.listen_port),
                               RequestHandler, server_config) 
    server.serve_forever()

if __name__ == '__main__':
    server_config = DOIPServerConfig(config_file = "srv.cfg")
    main(server_config)
