import sys
import socketserver
import ssl
import json
from jwcrypto import jwk
from datetime import datetime

#import DOIPio

default_target = "20.500.123/service"


class InputMessageProcessing():
    """
    This class is used for input message processing and is based 
    on rfile from the requestHandler.
    It provides the first and following sections, turns them into json.
    TODO: Currently only the first section

    if applicable and extracts special elements. 
       If threading is enabled on server using ThreadingMixIn
           - all local variables are independent and thread safe
           - all global variables and variables in for instance self.server = self.request_handler.server are not thread safe and should be written with care
           - all other variables in self.request_handler are independent and thread safe
    """
    def __init__(self, request_handler, inDOIPMessage, config):
        self.request_handler = request_handler
        self.inDOIPMessage = inDOIPMessage
        self.config = config
        #self.server = self.request_handler.server
        self.seg_terminator_found = None
        self.LogMsg = LogMsg(4)
        

    def getLeadingSegment(self):
        """
        returns the leading segment in DOIP format of a DOIP request 
        as array of lines of the leading segment. 
        Leaves the stream pointer in rfile on the current position.

        @return darray type array: lines of leading segment 
        """
        darray = []
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        while True:
            try:
                line = self.inDOIPMessage.readline().strip()
                if line == b'#' or line == b'@':
                    self.seg_terminator_found = line
                    break
                elif line == b'':
                    print("darray", darray)
                    self.LogMsg.warn(peer_address,"data stream ends without '#' after 1st segment")                        
                    break
                else:
                    darray.append(line)
            except BrokenPipeError:
                self.LogMsg.error(peer_address,"broken pipe while reading 1st segment")
                self.request_handler.DOIPstatus.set_code("other")
        return darray

    def getFollowingSegments(self):
        """
        Returns the following segments of a DOIP request as JSON element. 
        Uses the stream pointer in rfile on the current position.

        @return segm_array type array: array of all segments represented as arrays of lines 
        """
        segm_array = []
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        try:
            while True:
                if self.seg_terminator_found ==  b'@':
                    num_bytes_str = self.inDOIPMessage.readline().strip()
                    try:
                        num_bytes = int(num_bytes_str)
                    except:
                        self.LogMsg.error(peer_address,"invalid byte number declaration in byte segment")
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
                                self.LogMsg.warn(peer_address,"data stream ends without '#' after 1st segment")                        
                                break
                            else:
                                data += line
                        except BrokenPipeError:
                            self.LogMsg.error(peer_address,"broken pipe while reading 1st segment")
                segm_array.append(data)
        except BrokenPipeError:
            self.LogMsg.error(self.client_address,"broken pipe while reading following segments")
        return segm_array

    def _segment_to_json(self, data):
        """
        internal function that tries to get JSON out of data

        @param data type iterable object containing lines: input data
        @return jdata type json.object: data as json object
        """
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        obj = b''
        jdata = None
        for line in data:
            obj += line
        sdata = obj.decode()
        try:
            jdata = json.loads(sdata)
        except json.JSONDecodeError:
            self.LogMsg.error(peer_address, "JSONDecodeError")# + sdata)
        return jdata
        
    def _get_service_from_leading_json(self, jdata):
        """
        internal function that tries to get the service id 
        and its availabilty on this server out of JSON data.

        @param jdata type json.object: input data as json object
        @return service type string: service id
        @return avail type boolean: availabilty on this server
        """
        target = jdata["targetId"]
        operation = jdata["operationId"]
        service = operation + "@" + target
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        print (service, self.config.service_ids)
        try:
            if operation + "@" in self.config.service_ids[target]:
                self.LogMsg.info(peer_address,"service requested: " + operation, Method = " target: " + target + " on this server")
                avail = True
            else:
                self.LogMsg.error(peer_address,"unavailable service requested: " + operation, Method = " target: " + target)
                avail = False
        except:
            self.LogMsg.error(peer_address,"unavailable target requested: " + target, Method = " target: " + operation)
           
        return avail, service

class OutputMessageProcessing():
    """
    This class is used for output message processing and is based 
    on wfile from the requestHandler.
    It provides the output data sections and responds
    TODO: Currently only the first section

       If threading is enabled on server using ThreadingMixIn
           - all local variables are independent and thread safe
           - all global variables and variables in for instance self.server = self.request_handler.server are not thread safe and should be written with care
           - all other variables in self.request_handler are independent and thread safe
    """
        
    def __init__(self, request_handler, json_response, outfile):
        self.request_handler = request_handler
        self.json_response = json_response
        self.outfile = outfile

    def respond(self):
        """
        encodes and writes json in DOIP format to wfile from the requestHandler
        """
        response_encoded = json.dumps(self.json_response, sort_keys=True,indent=2, separators=(',', ' : ')).encode()
        response_encoded += ("\n" + "#" + "\n").encode()
        response_encoded += self.generate_output_data()
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        try:
            self.request_handler.wfile.write(response_encoded)
        except BrokenPipeError:
            self.LogMsg.error(peer_address,"broken pipe while writing output")
            self.request_handler.DOIPstatus.set_code("other")

    def generate_output_data(self):
        """
        dummy for generating output sections from the outfile buffer
        
        @return output_data type string: output sections 
        """
        if self.outfile == None:
            self.output_data = ("#" + "\n").encode()
        else:
            self.output_data = "".encode() # self.do_something_with_output_data() 
            self.output_data += ("#" + "\n").encode()
        return self.output_data
        
class status_codes():
    """
    Here the DOIP status codes and get and set functions are defined
    """
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
    
class LogMsg():
    """
    This class is used to format the log messages of the DOIP server 
    distinguished by debug, info, warn, error and host messages and 
    parametrized by the verbosity used for the server.
    """

    def __init__(self, verbosity):
        self.verbosity = verbosity
        
    def debug(self, client_address, msg, Method=''):
        """
        info messages: needed verbosity > 4
        """
        if self.verbosity < 5:
            return
        message = self._get_utcnow()+ ' DEBUG:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._shorten_msg(msg)
        if Method != '':
            message += ' with ' + Method
        # logging.debug(message)
        # app.logger.debug(message)
        sys.stdout.write(message + "\n")
        return

    def info(self, client_address, msg, Method=''):
        """
        info messages: needed verbosity > 2
        """
        if self.verbosity < 3:
            return
        message = self._get_utcnow()+ ' INFO:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._shorten_msg(msg)
        if Method != '':
            message += ' with ' + Method
        # logging.debug(message)
        # app.logger.debug(message)
        sys.stdout.write(message + "\n")
        return
    
    def warn(self, client_address, msg, Method=''):
        """
        warn messages: needed verbosity > 1
        """
        if self.verbosity < 2:
            return
        message = self._get_utcnow() + ' WARN:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._shorten_msg(msg)
        if Method != '':
            message += ' with ' + Method
        # logging.warning(message)
        # app.logger.warning(message)
        sys.stderr.write(message + "\n")
        return
    
    def host_message(self, client_address, msg):
        """
        host messages: needed verbosity > 1
        """
        if self.verbosity < 2:
            return
        message = self._get_utcnow() + ' HOST:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._shorten_msg(msg)
        # logging.info(message)
        # app.logger.debug(message)
        sys.stdout.write(message)
        return
    
    def error(self, client_address, msg,  Method=''):
        """
        error messages: needed verbosity > 0
        """
        if self.verbosity < 1:
            return
        message = self._get_utcnow() + ' ERROR:' + ' from ' + str(client_address[0]) + ':' + str(client_address[1]) + ' ' + self._shorten_msg(msg)
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

    def _shorten_msg(self,msg):
        try:
            msg[79]
            smsg = str(msg[:80]) + " ..."
        except IndexError:
            smsg = str(msg)
        return smsg





class DOIPServerConfig():

    def __init__(self,
                 service_ids = {
                     "20.500.123/service" : [
                         "0.DOIP/Op.Hello@",
                         "0.DOIP/Op.Create@",
                         "0.DOIP/Op.Retrieve@",
                         "0.DOIP/Op.Update@",
                         "0.DOIP/Op.Delete@",
                         "0.DOIP/Op.Search@",
                         "0.DOIP/Op.ListOperations@"
                     ]
                 },
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
        self.LogMsg = LogMsg(4) 
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
        operation = service.split("@")[0]
        target = service.split("@")[1]
        # Autorization policy to be implemented here
        try:
            if service.split("@")[0] + "@" in self.config.service_ids[target]:
                if (common_name != None and common_name.lower().split("@")[0] == "ulrich"):
                    accepted = True
        except:
            self.LogMsg.error(peer_address,"unavailable target requested: " + target, Method = " target: " + operation)
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

    def __init__(self, RequestHandlerClass, srv_cfg, operations, bind_and_activate=True):
        """
        initialize RequestHandler as ThreadingMixIn TCPServer
        setup server context including SSL support
        setup authentication methods and verification mode
        bind the socket and start the server
        @param RequestHandlerClass type socketserver.RequestHandler: type of RequestHandler
        @param srv_cfg type object: configuration parameters
        @param operations type DOIPServerOperationsClass: implemented DOIP Server Operation methods
        @param bind_and_activate type boolean: default True
        """
        self.LogMsg = LogMsg(4)
        
        self.config = srv_cfg
        self.server_address = (self.config.listen_addr, self.config.listen_port)
        # faster re-binding
        allow_reuse_address = srv_cfg.allow_reuse_address
        # make this bigger than five
        request_queue_size = srv_cfg.request_queue_size 
        # kick connections when we exit
        daemon_threads = srv_cfg.daemon_threads
        super().__init__(self.server_address, RequestHandlerClass, False)

        # setup server context including SSL support
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile=srv_cfg.server_cert, keyfile=srv_cfg.server_key)
        # replace the socket with an ssl version of itself
        self.socket = self.context.wrap_socket(self.socket, server_side=True)
        self.LogMsg.info(self.server_address,"is address of now initialized server", Method=srv_cfg.server_cert)
        # setup authentication methods and verification mode
        #    -  self.context.protocol is defined as  _SSLMethod.PROTOCOL_TLS
        #    -  self.config.context_verify_mode is defined as  VerifyMode.CERT_OPTIONAL
        #      ...
        self.auth = Auth_Methods(self.context, self.config)
        self.auth.client_verification_mode()
        self.cert_jwk = self.auth.get_server_certificate_jwk_json()
        self.DOIPRequest = operations
        self.DOIPRequest.set_server(self)

        # bind the socket and start the server
        if (bind_and_activate):
            try:
                self.server_bind()
                self.server_activate()
                self.LogMsg.info(self.server_address,"socket bound and server activated")
            except OSError as e:
                self.LogMsg.error(self.server_address,"socket not bound :" + repr(e))
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
        self.DOIPStatusCodes = status_codes()
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
        DOIPRequest = InputMessageProcessing(self, self.rfile, self.server.config)
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
        output_json = self.server.DOIPRequest.operateService(service, json_input, self.rfile)
        return output_json
        
    def handleOutputMessage(self, output_json):
        DOIPResponse = OutputMessageProcessing(self, output_json, self.wfile)
        DOIPResponse.respond()

class DOIPServerOperations():
    def __init__(self):
        None

    def set_server(self, server):
        self.server = server

    def operateService(self, service, jsondata, rfile):
        pass

    def operate_Hello(self, service, jsondata, rfile) :
        pass

    def operate_Create(self, service, jsondata, rfile) :        
        pass

    def operate_Retrieve(self, service, jsondata, rfile) :
        pass

    def operate_Update(self, service, jsondata, rfile) :
        pass

    def operate_Delete(self, service, jsondata, rfile) :        
        pass

    def operate_Search(self, service, jsondata, rfile) :
        pass
    
    def operate_ListOperations(self, service, jsondata, rfile) :
        pass

    def operate_Other(self, service, jsondata, rfile) :
        pass

