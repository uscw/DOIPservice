import sys
import socketserver
import ssl
import json
from datetime import datetime
from jwcrypto import jwk

class DOIPServerConfig():

    def __init__(self,
                 service_ids = ['20.500.123/service'],
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
        self.LogMsg = LogMsg()
        self.service_ids =         service_ids
        self.listen_addr =         listen_addr
        self.listen_port =         listen_port
        self.server_cert =         server_cert
        self.server_key =          server_key
        self.client_cert =         client_cert
        self.request_queue_size =  request_queue_size
        self.daemon_threads =      daemon_threads
        self.allow_reuse_address = allow_reuse_address
        self.context_verify_mode = context_verify_mode
        if config_file != None:
            self.read_config_file(config_file)

            
    def read_config_file(self, config_file):
        fd = open(config_file)
        cfg = json.loads(fd.read())
        try:
            self.service_ids =         cfg["service_ids"]
            self.listen_addr =         cfg["listen_addr"]
            self.listen_port =         cfg["listen_port"]
            self.server_cert =         cfg["server_cert"]
            self.server_key =          cfg["server_key"]
            self.client_cert =         cfg["client_cert"]
            self.request_queue_size =  cfg["request_queue_size"]
            self.daemon_threads =      cfg["daemon_threads"]
            self.allow_reuse_address = cfg["allow_reuse_address"]
            self.context_verify_mode = eval(cfg["context_verify_mode"])
        except KeyError as e:
            sinfo = ( repr(e), " in Config File:" )
            self.LogMsg.error( sinfo , config_file , " using the Default instead" )
        return

class LogMsg():

    def __init__(self):
        None
        
    def info(self, client_address, msg, Method=''):
        """
        """
        message = self._get_utcnow()+ ' INFO:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._short_msg(msg)
        if Method != '':
            message += ' with ' + Method
        # logging.debug(message)
        # app.logger.debug(message)
        sys.stdout.write(message + "\n")
        return
    
    def warn(self, client_address, msg, Method=''):
        """
        """
        message = self._get_utcnow() + ' WARN:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._short_msg(msg)
        if Method != '':
            message += ' with ' + Method
        # logging.warning(message)
        # app.logger.warning(message)
        sys.stderr.write(message + "\n")
        return
    
    def host_message(self, client_address, msg):
        """
        """
        message = self._get_utcnow() + ' HOST:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._short_msg(msg)
        # logging.info(message)
        # app.logger.debug(message)
        sys.stdout.write(message)
        return
    
    def error(self, client_address, msg,  Method=''):
        """
        """
        message = self._get_utcnow() + ' ERROR:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._short_msg(msg)
        if Method != '':
            message += ' with ' + Method
        # logging.error(message)
        # app.logger.error(message)
        sys.stderr.write(message + "\n")

    def _get_utcnow(self):
        """
        returns UTC current time in format "%Y-%m-%dT%H:%M:%S+00:00"
        """
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def _short_msg(self,msg):
        try:
            msg[79]
            smsg = str(msg[:80]) + " ..."
        except IndexError:
            smsg = str(msg)
        return smsg

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

    def get_authentication(self, request_handler, request_cert, client_address):
        """
        represents the authentication
        @param request_cert type 
        """
        common_name = None
        try:
            common_name = self._get_certificate_common_name(request_cert)
            request_handler.server.LogMsg.info(client_address,"common_name: " + common_name )
        except BrokenPipeError:
            request_handler.server.LogMsg.error(client_address,"broken pipe during authentication from")
        return common_name
    
    def get_authorization(self, common_name, service, client_address):
        # optionally check client certificate with whitelist, disabled here
        accepted = True
        if service == "ll":
            if (common_name is None or common_name.split("@") != "ulrich"):
                request_handler.server.LogMsg.info(client_address,"rejecting common_name: {}".format(common_name))
                accepted = False
        return accepted
        
    def _get_certificate_common_name(self, cert):
        if (cert is None):
            return None
        for sub in cert.get("subject", ()):
            for key, value in sub:
                if (key == "commonName"):
                    return value

    def get_server_certificate_jwk_json(self):
        self.this_jwk = jwk.JWK
        fd = open(self.config.server_cert)
        cert = ""
        for line in fd.readlines():
            cert += line
        cert_jwk = self.this_jwk.from_pem(cert.encode())
        return cert_jwk.export()
                
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
        self.LogMsg = LogMsg()
        
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
        self.LogMsg.info(server_address,"is address of now initialized server", Method=srv_cfg.server_cert)
        
        # setup authentication methods and verification mode
        #      self.context.protocol is _SSLMethod.PROTOCOL_TLS
        #      self.config.context_verify_mode is VerifyMode.CERT_OPTIONAL
        #      ...
        self.auth = Auth_Methods(self.context, self.config)
        self.auth.client_verification_mode()
        self.cert_jwk = self.auth.get_server_certificate_jwk_json()
        
        # bind the socket and start the server
        if (bind_and_activate):
            try:
                self.server_bind()
                self.server_activate()
                self.LogMsg.info(server_address,"socket bound and server activated")
            except OSError as e:
                self.LogMsg.error(server_address,"socket not bound :" + repr(e))
                sys.exit(1)

class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        """
        Supersedes the handle() method in the BaseRequestHandler class of socketserver.
        Handles requests and answers after authentication and authorization.
        Provides self.rfile and self.wfile for stream sockets.
        Inherites the server and request environment from socketserver.BaseRequestHandler
        Threading: enabled by server using ThreadingMixIn
           - all local variables are independent and thread safe
           - all global variables and variables in for instance self.server are not thread safeand cannot be written without care
        """
        self.server.LogMsg.info(self.client_address,"connection initialized")
        self.DOIPstatus = DOIP_status()

        try:
            request_cert = self.request.getpeercert()
            print (request_cert, self.request.cipher(), self.server.cert_jwk)
        except BrokenPipeError:
            self.server.LogMsg.error(self.client_address,"broken pipe while getting peer cert")

        # authentication
        cname = self.server.auth.get_authentication(self, request_cert, self.client_address)
        if cname == None:
            self.DOIPstatus.set_code("unauthenticated")
        else:
            service, json_input = self.handleInputMessage()

            # authorization
            accepted = self.server.auth.get_authorization(cname, service, self.client_address)
            if not accepted:
                 self.DOIPstatus.set_code("unauthorized")
            else:
                output_data = ""
                if service == None:
                    self.DOIPstatus.set_code("object_unknown")
                else:
                    output_data = self.handleOperation(json_input, service, input_data = "")
                    if self.DOIPstatus.code == None:
                        self.DOIPstatus.set_code("other")                    
        self.handleOutputMessage(service, output_data)

    def handleInputMessage(self):
        """
        Gets the first segment from input and returns the json element in this segment.
        The rfile stays open with pointer on the first line after the '#' delimiter.
        The other segments are handled by the output handle in self.handleOutputMessage().

        @return service type string:  service type identifier
        @return jdata type json:  json element in first segment 
        """
        DOIPRequest = DOIPServerRequestImplementation(self,self.rfile)
        # now listen to client
        segment_1st = DOIPRequest.getLeadingSegment()
        jdata = DOIPRequest._segment_to_json(segment_1st)
        available, service = DOIPRequest._get_service_from_leading_json(jdata)
        if not available:
            service = None
        return service, jdata

    def handleOperation(self, json_input, service, input_data):
        """
        The rfile stays open with pointer on the first line after the '#' delimiter.
        The other segments are handled by the output handle in self.handleOutputMessage().

        @return output_data type array of streams: output of service
        """
        DOIPRequest = DOIPServerOperationImplementation(self, json_input, service)
        output_data = "".encode()
        return output_data
        
    def handleOutputMessage(self, service, output_data):
        output_json = {
            "status":self.DOIPstatus.set_code("success"),
            "output":{
                "id":service,
                "type":"0.TYPE/DOIPService",
                "attributes":{
                    "ipAddress":self.server.config.listen_addr,
                    "port":self.server.config.listen_port,
                    "protocol":"TCP",
                    "protocolVersion":"2.0",
                    "publicKey": self.server.cert_jwk
                }
            }
        }
        DOIPResponse = DOIPServerResponseImplementation(self, output_json, output_data)
        DOIPResponse.respond()

class DOIPServerRequestImplementation():
    def __init__(self, request_handler, inDOIPMessage):
        """
        Threading: enabled by server using ThreadingMixIn
           - all local variables are independent and thread safe
           - all global variables and variables in for instance self.server = self.request_handler.server are not thread safe and cannot be written without care
           - all other variables in self.request_handler are independent and thread safe
        """
        self.request_handler = request_handler
        self.inDOIPMessage = inDOIPMessage
        self.server = self.request_handler.server
        self.seg_terminator_found = None

    def getLeadingSegment(self):
        """
        returns the leading segment of a DOIP request as array of lines of the leading segment. 
        Leaves the stream pointer in rfile on the current position.

        @return darray type array: lines of leading segment 
        """
        darray = []
        while True:
            try:
                line = self.request_handler.rfile.readline().strip()
                if line == b'#' or line == b'@':
                    self.seg_terminator_found = line
                    break
                elif line == b'':
                    self.server.LogMsg.warn(self.request_handler.client_address,"data stream ends without '#' after 1st segment")                        
                    break
                else:
                    darray.append(line)
            except BrokenPipeError:
                self.server.LogMsg.error(self.request_handler.client_address,"broken pipe while reading 1st segment")
                self.request_handler.DOIPstatus.set_code("other")
        return darray

    def getFollowingSegments(self):
        """
        Returns the following segments of a DOIP request as JSON element. 
        The stream pointer in rfile on the current position.

        @return segm_array type array: array of all segments represented as arrays of lines 
        """
        segm_array = []
        try:
            while True:
                if self.seg_terminator_found ==  b'@':
                    num_bytes_str = self.request_handler.rfile.readline().strip()
                    try:
                        num_bytes = int(num_bytes_str)
                    except:
                        self.server.LogMsg.error(self.request_handler.client_address,"invalid byte number declaration in byte segment")
                        self.request_handler.DOIPstatus.set_code = "invalid"
                else:
                    data = ""
                    while True:
                        try:
                            line = self.request_handler.rfile.readline().strip()
                            if line == b'#' or b'@':
                                self.seg_terminator_found = line
                                break
                            elif line == b'':
                                self.server.LogMsg.warn(self.request_handler.client_address,"data stream ends without '#' after 1st segment")                        
                                break
                            else:
                                data += line
                        except BrokenPipeError:
                            self.server.LogMsg.error(self.request_handler.client_address,"broken pipe while reading 1st segment")
                segm_array.append(data)
        except BrokenPipeError:
            self.server.LogMsg.error(self.client_address,"broken pipe while reading following segments")
        return segm_array

    def _segment_to_json(self, data):
        obj = b''
        jdata = None
        for line in data:
            obj += line
        sdata = obj.decode()
        try:
            jdata = json.loads(sdata)
        except json.JSONDecodeError:
            self.server.LogMsg.error(self.request_handler.client_address, "JSONDecodeError")# + sdata)
        return jdata
        
    def _get_service_from_leading_json(self, jdata):
        target = jdata["targetId"]
        operation = jdata["operationId"]
        service = operation + "@" + target
        if target in self.server.config.service_ids:
            self.server.LogMsg.info(self.request_handler.client_address,"service requested: " + operation, Method = "method on this server")
            avail = True
        else:
            self.server.LogMsg.error(self.request_handler.client_address,"service requested: " + operation, Method = "wrong target: " + target)
            avail = False
        return avail, service

    def splitIterator(self, inDOIPMessage):
        if (ch == 35): # char = '#'
            None
        if (ch == 48): # char = '0', Exception:  "zero at start of chunk size"
            None
        if (ch == -1): # char = '-1', Exception: "end of input reading chunk size"
            None
        if (ch == 10 or ch == 32 or ch == 9 or ch == 13):
            # char10 = '\n ' Line Feed', char32 = ' ' , space, char9 = '\t' Horizontal Tab, char13 = '\r'	Carriage Return, Exception: "check chunk size"
            None
        if (ch < 48 or ch > 57): # "unexpected character in chunk size"
            None

        if (ch == 35): # char = '#'
            None
            # InDoipMessageImpl.this.skipToNewline();
            # InDoipMessageImpl.this.isClosed = true;
            # if (InDoipMessageImpl.this.completer != null)
            #   InDoipMessageImpl.this.completer.complete(null); 
            # return false;

        if (ch == 64): #  char = '@'
            None
            #   InDoipMessageImpl.this.skipToNewline();
            #   InDoipMessageImpl.this.curr = new InDoipSegmentFromInputStream(false, new InDoipMessageImpl.ChunkedBytesInputStream());
            # else
            #   InDoipMessageImpl.this.in.unread(ch);
            #   InDoipMessageImpl.this.curr = new InDoipSegmentFromInputStream(true, new InDoipMessageImpl.HashTerminatedInputStream());

class DOIPServerOperationImplementation():
    
    def __init__(self, server, data, service):
        self.server = server
        self.data = data
        self.service = service

    def handleOperation(self):
        if not accepted:
            ret = '{"accepted": false}\n'.encode()
        else:
            ret = '{"accepted": true}\n'.encode()
        return ret
 
class DOIPServerResponseImplementation():
    
    def __init__(self, request_handler, json_response, output_data):
        self.request_handler = request_handler
        self.json_response = json_response
        self.output_data = output_data

    def respond(self):
        response_encoded = json.dumps(self.json_response, sort_keys=True,indent=2, separators=(',', ' : ')).encode()
        response_encoded += ("\n" + "#" + "\n").encode()
        response_encoded += self.output_data
        response_encoded += ("\n" + "#" + "\n").encode()
        self.request_handler.wfile.write(response_encoded)

class DOIP_status():

    def __init__(self):
        self.codes = {
            # The operation was successfully processed.
            "success"                       : "0.DOIP/Status.001",
            # The request was invalid in some way.
            "invalid"                       : "0.DOIP/Status.101",
            # The client did not successfully authenticate.
            "unauthenticated"               : "0.DOIP/Status.102",
            # The client successfully authenticated, but is unauthorized to invoke the operation.
            "unauthorized"                  : "0.DOIP/Status.103",
            # The digital object is not known to the service to exist.
            "object_unknown"                : "0.DOIP/Status.104",
            # The client tried to create a new digital object with an identifier already in use by an existing digital object.
            "creation_on_existing_object"   : "0.DOIP/Status.105",
            # The service declines to execute the extended operation.
            "extended_operation_declined"   : "0.DOIP/Status.200",
            # Error other than the ones stated above occurred.
            "other"                         : "0.DOIP/Status.500"
        }
        self.code = None 

    def set_code(self,status):
        self.code = self.codes[status]
        return self.code

    def get_code(self):
        return self.code
    
           
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
