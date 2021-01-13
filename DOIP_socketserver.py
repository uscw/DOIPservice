import sys
import socketserver
import ssl
import json
from jwcrypto import jwk

import DOIPss

default_target = "20.500.123/service"

class DOIPServerConfig():

    def __init__(self,
                 service_ids = ["0.DOIP/Op.Hello@20.500.123/service", "0.DOIP/Op.Create@20.500.123/service", "0.DOIP/Op.Retrieve@20.500.123/service", "0.DOIP/Op.Update@20.500.123/service", "0.DOIP/Op.Delete@20.500.123/service", "0.DOIP/Op.Search@20.500.123/service", "0.DOIP/Op.ListOperations@20.500.123/service"],
                 listen_addr = "127.0.0.1",
                 listen_port = 8443,
                 server_cert = "certs/server.crt",
                 server_key = "certs/server.key",
                 client_cert = "certs/clients.txt",
                 request_queue_size = 10,
                 daemon_threads = True,
                 allow_reuse_address = True,
                 config_file = None,
                 context_verify_mode = ssl.CERT_OPTIONAL
    ):
        """
        DOIP Server Configuration with optional parameters to override default values.
        If a config file is given, this will be used to override the default values.

        @param service_ids         type list of string: allowed service identifer
        @param listen_addr         type string: address where server listens
        @param listen_port         type int: port where server listens
        @param server_cert         type string: file of server certificate
        @param server_key          type string: file of server prvate key
        @param client_cert         type string: file of allowed client certificates
        @param request_queue_size  type int: size of request queue
        @param daemon_threads      type boolean: daemon threads allowed
        @param allow_reuse_address type boolean: reuse of address allowed
        @param config_file         type string: name of configuration file
        @param context_verify_mode type ssl-type: kind of verification mode
        """
        self.LogMsg = DOIPio.LogMsg(4) 
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
        """
        read a config file to override the default values.
        Content of file:
        service_ids         type list of string: allowed service identifer
        listen_addr         type string: address where server listens
        listen_port         type int: port where server listens
        server_cert         type string: file of server certificate
        server_key          type string: file of server prvate key
        client_cert         type string: file of allowed client certificates
        request_queue_size  type int: size of request queue
        daemon_threads      type boolean: daemon threads allowed
        allow_reuse_address type boolean: reuse of address allowed
        context_verify_mode type ssl-type: kind of verification mode

        """        
        fd = open(config_file)
        fdin = ""
        for line in fd.readlines():
            if line.strip()[0] != "#":
                fdin += line.strip()
        cfg = json.loads(fdin)
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

class Auth_Methods():
    def __init__(self, context, config):
        """
        Defines authentication mode, provides authorization and authentication for a DOIPRequestServer

        @param context type context of DOIPRequestServer: context of server
        @param config type configuration of DOIPRequestServer: configuration of server
        """
        self.context = context
        self.config = config

    def client_verification_mode(self):
        """
        require special certs for connection with the following SSL parameters:
          CERT_NONE - no certificates from the other side are required (or will be looked at if provided)
          CERT_OPTIONAL - certificates are not required, but if provided will be validated, and if validation fails, the connection will also fail
          CERT_REQUIRED - certificates are required, and will be validated, and if validation fails, the connection will also fail
        also verifies source locations, if cert and key are provided by client, cert needs to be known in srv_cfg.client_cert (authorization)
        """
        self.context.verify_mode = self.config.context_verify_mode # ssl.CERT_OPTIONAL
        self.context.load_verify_locations(cafile=self.config.client_cert)

    def get_authentication(self, request_handler, request_cert, client_address):
        """
        provides the authentication for DOIPRequestServer

        @param request_handler type socketserver.RequestHandler: request handler of DOIPRequestServer: 
        @param request_cert type certificate: peer certificate of request
        @param client_address type string: address of client request
        @return common_name type string: common name if resolved, else None
        """
        common_name = None
        try:
            common_name = self._get_certificate_common_name(request_cert)
            request_handler.server.LogMsg.info(client_address,"common_name: " + common_name )
        except BrokenPipeError:
            request_handler.server.LogMsg.error(client_address,"broken pipe during authentication from")
        return common_name
    
    def get_authorization(self, request_handler, common_name, service, client_address):
        """
        provides the authorization for DOIPRequestServer. Here the policies for authorization are implemented (currently service 

        @param request_handler type socketserver.RequestHandler: request handler of DOIPRequestServer
        @param common_name type string: common name if resolved, else None
        @param service type 
        @param client_address type string: address of client request
        @result accepted type boolean: True if accepted
        """
        accepted = self._is_authorized_by_policy(service,common_name)
        # optionally check client certificate with whitelist, disabled here
        if accepted:
            request_handler.server.LogMsg.info(client_address,"accepting service {} for common_name: {}".format(service, common_name))
        else:
            request_handler.server.LogMsg.info(client_address,"rejecting  service {} for common_name: {}".format(service, common_name))
        return accepted

    def _is_authorized_by_policy(self, service, common_name):
        """
        Here the policies for authorization are implemented for given common name and service

        @param service type string: requested service
        @param common_name type string: requesting common name
        @result accepted type boolean: True if accepted
        """
        accepted = False
        # Autorization policy to be implemented here
        if service.split("@")[0] + "@" in self.config.service_ids:
            if (common_name != None and common_name.lower().split("@")[0] == "ulrich"):
                accepted = True
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
        self.LogMsg = DOIPio.LogMsg(4)
        
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
        #    -  self.context.protocol is defined as  _SSLMethod.PROTOCOL_TLS
        #    -  self.config.context_verify_mode is defined as  VerifyMode.CERT_OPTIONAL
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
        self.DOIPStatusCodes = DOIPio.status_codes()
        output_json = {}
# authentication
        try:
            request_cert = self.request.getpeercert()
            # print (request_cert, self.request.cipher(), self.server.cert_jwk)
        except BrokenPipeError:
            self.server.LogMsg.error(self.client_address,"broken pipe while getting peer cert")
        cname = self.server.auth.get_authentication(self, request_cert, self.client_address)
        if cname == None:
            self.DOIPStatusCodes.set_code("unauthenticated")
        else:
# Input Processing
            service, json_input = self.handleInputMessage()
            if service == None:
                self.DOIPStatusCodes.set_code("object_unknown")
                output_data = None
            else:
# authorization
                accepted = self.server.auth.get_authorization(self, cname, service, self.client_address)
                if not accepted:
                    self.DOIPStatusCodes.set_code("unauthorized")
                else:
# Operation
                    output_json = self.handleOperation(json_input, service, input_data = "")
                    if output_json != None:
                        self.DOIPStatusCodes.set_code("success")
        if output_json == None or self.DOIPStatusCodes.code == None:
            self.DOIPStatusCodes.set_code("other")
            output_json = {}
# Output Processing
        output_json["status"] = self.DOIPStatusCodes.get_code()
        self.handleOutputMessage(output_json)

    def handleInputMessage(self):
        """
        Gets the first segment from input and returns the json element in this segment.
        The rfile stays open with pointer on the first line after the '#' delimiter.
        The other segments are handled by the output handle in self.handleOutputMessage().

        @return service type string:  service type identifier
        @return jdata type json:  json element in first segment 
        """
        DOIPRequest = DOIPio.InputMessageProcessing(self, self.rfile, self.server.config)
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
        output_json = DOIPRequest.operateService()
        return output_json
        
    def handleOutputMessage(self, output_json):
        DOIPResponse = DOIPio.OutputMessageProcessing(self, output_json, self.wfile)
        DOIPResponse.respond()

class DOIPServerOperationImplementation():
    
    def __init__(self, requestHandler, data, service):
        self.requestHandler = requestHandler
        self.data = data
        self.service = service
        self.rfile = self.requestHandler.rfile
        self.wfile = None

    def operateService(self):
        operation = self.service.split("@")[0]
        target = self.service.split("@")[1]
        ret = {}
        if target == default_target:
            if operation == "0.DOIP/Op.Hello" :
                ret = self.operate_Hello()
            elif operation == "0.DOIP/Op.Create" : 
                ret = self.operate_Create()
            elif operation == "0.DOIP/Op.Retrieve" : 
                ret = self.operate_Retrieve()
            elif operation == "0.DOIP/Op.Update" : 
                ret = self.operate_Update()
            elif operation == "0.DOIP/Op.Delete" : 
                ret = self.operate_Delete()
            elif operation == "0.DOIP/Op.Search" : 
                ret = self.operate_Search()
            elif operation == "0.DOIP/Op.ListOperations" : 
                ret = self.operate_ListOperations()
        return ret

    def operate_Hello(self) :
        attr = {}
        attr["ipAddress"] = self.requestHandler.server.config.listen_addr
        attr["port"] = self.requestHandler.server.config.listen_port
        attr["protocol"] = "TCP"
        attr["protocolVersion"] = "2.0"
        attr["publicKey"] = json.loads(self.requestHandler.server.cert_jwk)
        output = {}
        output["id"] = self.service
        output["type"] = "0.TYPE/DOIPService"
        output["attributes"] = attr
        output_json = {}
        output_json["status"] = None
        output_json["output"] = output
        self.wfile = None
        return output_json

    def operate_Create(self) :        
        ret = {}
        return ret

    def operate_Retrieve(self) :
        ret = {}
        return ret

    def operate_Update(self) :
        ret = {}
        return ret

    def operate_Delete(self) :        
        ret = {}
        return ret

    def operate_Search(self) :
        ret = {}
        return ret
    
    def operate_ListOperations(self) :
        target = self.service.split("@")[1]
        output = []
        for item in self.requestHandler.server.config.service_ids:
            if item.split("@")[1] == target:
                output.append(item.split("@")[0])
        output_json = {}
        output_json["status"] = None
        output_json["output"] = output 
        self.wfile = None
        return output_json

    
########## main ###########           
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
