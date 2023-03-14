import sys
import socketserver
import logging
import ssl
import json
import asyncio
from jwcrypto import jwk
from datetime import datetime

#import DOIPio

default_target = "20.500.123/service"
default_dir = "/home/uschwar1/ownCloud/AC/python/xmpls/DOIP_socketserver/"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    stream=sys.stderr,
)
log = logging.getLogger('main')




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
        self.LogMsg = logging.getLogger('InputMessageProcessing')
        

    async def getLeadingJsonSegment(self):
        """
        returns the leading segment in DOIP format of a DOIP request 
        as array of lines of the leading segment. 
        Leaves the stream pointer in rfile on the current position.

        @return darray type array: lines of leading segment 
        """
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        json_input = b''
        while True:
            try:
                line = await self.inDOIPMessage.readline() # skip trailing "\n"
                if len(line) == 0: 
                    self.LogMsg.debug(str(peer_address) + " input data stream ends with EOF")                        
                    return json_input, line[:-1] # EOF reached
                elif line[:-1] == b'':
                    self.LogMsg.warn(str(peer_address) + " data stream ends with empty line and without '#' after 1st segment")                        
                    return json_input, line[:-1] # treated as if EOF reached
                elif line[:-1] == b'#':
                    self.seg_terminator_found = line[:-1]
                    # print ("# terminator", line)
                    break
                #elif  line[0] == b'@':
                elif line.startswith(b'@'):
                    self.seg_terminator_found = line[:-1]
                    # print ("@ terminator", line)
                    break                    
                else:
                    json_input += line[:-1]
            except BrokenPipeError:
                self.LogMsg.error(str(peer_address) + " broken pipe while reading 1st segment")
                self.request_handler.DOIPstatus.set_code("other")
        # print ("json_input",json_input)
        return json_input, line[:-1]

    
    def _segment_to_json(self, data):
        """
        internal function that tries to get JSON out of data

        @param data type iterable object containing lines: input data
        @return jdata type json.object: data as json object
        """
        # print("data in _segment_to_json",data)
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        jdata = None
        sdata = data.decode()
        try:
            jdata = json.loads(sdata)
        except json.JSONDecodeError:
            self.LogMsg.error(str(peer_address) + " JSONDecodeError")# + sdata)
            jdata = None
        return jdata
        
    def _get_service_from_leading_json(self, jdata):
        """
        internal function that tries to get the service id 
        and its availabilty on this server out of JSON data.

        @param jdata type json.object: input data as json object
        @return service type string: service id
        @return avail type boolean: availabilty on this server
        """
        avail = False
        service = None
        # print ("jdata",jdata)
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        try:
            target = jdata["targetId"]
            operation = jdata["operationId"]
            service = operation + "@" + target
        except:
            self.LogMsg.info(str(peer_address) + " service requires json with targetId and operationId in first segment" )
        # print (service, self.config.service_ids)
        if service != None:
            try:
                if operation in self.config.service_ids[target]:
                    self.LogMsg.debug(str(peer_address) + " service requested: " + operation + ", target: " + target + " on this server")
                    avail = True
                else:
                    self.LogMsg.error(str(peer_address) + " unavailable service requested: " + operation + ", target: " + target)
            except:
                self.LogMsg.error(str(peer_address) + " unavailable target requested: " + target + ", target: " + operation)
        return avail, service

class OutputMessageProcessing():
    """
    This class is used for output message processing and is based 
    on wfile from the requestHandler.
    It provides the output data sections and responds

       If threading is enabled on server using ThreadingMixIn
           - all local variables are independent and thread safe
           - all global variables and variables in for instance self.server = self.request_handler.server are not thread safe and should be written with care
           - all other variables in self.request_handler are independent and thread safe
    """
        
    def __init__(self, request_handler, json_response, outfile):
        self.request_handler = request_handler
        self.json_response = json_response
        self.outfile = outfile
        self.LogMsg = logging.getLogger('OutputMessageProcessing')

    async def respond(self):
        """
        encodes and writes json in DOIP format to wfile from the requestHandler
        """
        # print ("OutputMessageProcessing, respond: ", self.json_response)
        # response = json.dumps(self.json_response, sort_keys=True,indent=2, separators=(',', ' : '))
        response = str(self.json_response)
        response_encoded = response.encode()
        response_encoded += ("\n" + "#" + "\n").encode()
        response_encoded += self.generate_output_data()
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        try:
            self.request_handler.wfile.write(response_encoded)
            self.LogMsg.info("output written to " +  str(peer_address))
            await self.request_handler.wfile.drain()
        except BrokenPipeError:
            self.LogMsg.error(str(peer_address) + " broken pipe while writing output")
            self.request_handler.DOIPstatus.set_code("other")
        except ConnectionResetError:
            self.LogMsg.error(str(peer_address) + " connection lost while draining writer")
            

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
    
class DOIPServerConfig():

    def __init__(self,
                 service_ids = {
                     "20.500.123/service" : [
                         "0.DOIP/Op.Hello",
                         "0.DOIP/Op.Create",
                         "0.DOIP/Op.Retrieve",
                         "0.DOIP/Op.Update",
                         "0.DOIP/Op.Delete",
                         "0.DOIP/Op.Search",
                         "0.DOIP/Op.ListOperations"
                     ]
                 },
                 listen_addr = "127.0.0.1",
                 listen_port = 8443,
                 server_cert = default_dir + "certs/server.crt",
                 server_key = default_dir + "certs/server.key",
                 client_cert = default_dir + "certs/clients.txt",
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
        self.LogMsg = logging.getLogger('DOIPServerConfig')
        self.service_ids =         service_ids        
        self.listen_addr =         listen_addr        
        self.listen_port =         listen_port        
        self.server_cert =         server_cert
        # print (server_cert)
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
            self.allow_unauthenticated_access = cfg["allow_unauthenticated_access"]
            self.context_verify_mode = eval(cfg["context_verify_mode"])
        except KeyError as e:
            self.LogMsg.error( str(repr(e)) + " in Config File:" + config_file + " using the Default instead" )
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
        self.LogMsg = logging.getLogger('Auth_Methods')

    def client_verification_mode(self):
        """
        require special certs for connection with the following SSL parameters:
          CERT_NONE - no certificates from the other side are required (or will be looked at if provided)
          CERT_OPTIONAL - certificates are not required, but if provided will be validated, and if validation fails, the connection will also fail
          CERT_REQUIRED - certificates are required, and will be validated, and if validation fails, the connection will also fail
        also verifies source locations, if cert and key are provided by client, cert needs to be known in srv_cfg.client_cert (authorization)
        """
        self.context.verify_mode = self.config.context_verify_mode # ssl.CERT_OPTIONAL
        self.context.load_verify_locations(cafile=default_dir + self.config.client_cert)

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
            if common_name == None:
                self.LogMsg.debug(str(client_address) + " common_name: " + str(common_name) + " changed to 'unknown_client'")
                common_name = "unknown_client"
        except BrokenPipeError:
            self.LogMsg.error(str(client_address) + " broken pipe during authentication from")
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
            self.LogMsg.info(str(client_address) + " accepting service {} for common_name: {}".format(service, common_name))
        else:
            self.LogMsg.info(str(client_address) + " rejecting service {} for common_name: {}".format(service, common_name))
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
        # Authorization policy to be implemented here
        try:
            if operation in self.config.service_ids[target]:
                if operation == "0.DOIP/Op.Hello" or operation == "0.DOIP/Op.ListOperations":
                    accepted = True
                elif (common_name != None and common_name.lower().split("@")[0] == "ulrich"):
                    accepted = True
                else:
                    self.LogMsg.warning("operation " + operation + " not available for common name: " + common_name )
            else:
                self.LogMsg.warning("operation " + operation + "not available at this server for target: " + target )
        except:
            self.LogMsg.error( "for common name: " + common_name + " unavailable target requested: " + target + " target: " + operation)
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
        fd = open(default_dir + self.config.server_cert)
        cert = ""
        for line in fd.readlines():
            cert += line
        cert_jwk = self.this_jwk.from_pem(cert.encode())
        return cert_jwk.export()
                

##########################
class asyncioRequestHandler():
    def __init__(self, config, operations):
        self.config = config
        self.operations = operations
        config_path = "/home/uschwar1/ownCloud/AC/python/xmpls/DOIP_socketserver/"
        self.server_cert = config_path + self.config.server_cert #"certs/server.crt"
        self.server_key =  config_path + self.config.server_key #"certs/server.key"
        self.server_addr = self.config.listen_addr
        self.server_port = self.config.listen_port
        
        # setup server context including SSL support
        self.SSL_CONTEXT = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.SSL_CONTEXT.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)
        self.auth = Auth_Methods(self.SSL_CONTEXT, self.config)
        self.auth.client_verification_mode()
        self.cert_jwk = self.auth.get_server_certificate_jwk_json()

        
    async def start_server(self):
        self.IPaddress = '127.0.0.1'
        self.port = 10000
        self.LogMsg = logging.getLogger('AsyncIO_RequestHandler')
        try:
            self.server = await asyncio.start_server(self.handle, self.server_addr, self.server_port, ssl=self.SSL_CONTEXT)
        except OSError: # with e:
            self.LogMsg.error("Unable to start server. Address ("  + self.IPaddress + ":"+ str(self.port) + ") already in use?" )
            sys.exit(1)
        self.server_address = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
        self.LogMsg.info("Serving on " + str(self.server_address))
        
        async with self.server:
            await self.server.serve_forever()

    async def handle(self, reader, writer):
        """
        Handles requests and answers after authentication and authorization.
        Provides self.reader and self.writer .
        """
        self.rfile = reader
        self.wfile = writer
        self.client_address = self.rfile._transport.get_extra_info('peername')
        self.writer_address = self.wfile._transport.get_extra_info('peername')
        self.LogMsg.info(str(self.client_address) + " connection initialized")
        self.DOIPStatusCodes = status_codes()
        output_json = {}
#################
# authentication
#################
        try:
            self.request_cert = self.rfile._transport.get_extra_info('peercert')
            # print (self.request_cert, self.request.cipher(), self.server.cert_jwk)
        except BrokenPipeError:
            self.LogMsg.error(str(self.client_address) + " broken pipe while getting peer cert")
        cname = self.auth.get_authentication(self, self.request_cert, str(self.client_address))
        if cname == None:
            self.DOIPStatusCodes.set_code("unauthenticated")
            self.LogMsg.error(str(self.client_address) + " request could not be authenticated")
            # output_json = b'{ "status" : self.DOIPStatusCodes.get_code() }'
        else:
            while True:
#################
# Input Processing
#################
                self.DOIPRequest = InputMessageProcessing(self, self.rfile, self.config)
                service, json_input, lastLine = await self.handleInputMessage()
                if lastLine == b'':
                    self.LogMsg.info(str(self.client_address) + " input stream terminated")
                    output_json = { "status" : "EOF" }
                    break
                if service == None:
                    self.DOIPStatusCodes.set_code("invalid")
                    self.LogMsg.info(str(self.client_address) + " input invalid")
                    output_json = { "status" : self.DOIPStatusCodes.get_code() }
                else:
#################
# authorization
#################
                    accepted = self.auth.get_authorization(self, cname, service, self.client_address)
                    if not accepted:
                        self.DOIPStatusCodes.set_code("unauthorized")
                        self.LogMsg.info(str(self.client_address) + " connection unauthorized")
                        output_json = { "status" : self.DOIPStatusCodes.get_code() }
                    else:
#################
# Operation
#################
                        output_json = await self.handleOperationOnFurtherSegments(json_input, service, lastLine)
                        # print ("Operation gives Output: ", output_json, isinstance(output_json,dict),  "status" not in output_json)
                        if output_json != None and isinstance(output_json,dict) and "status" not in output_json:
                            self.DOIPStatusCodes.set_code("success")
                            self.LogMsg.info(str(self.client_address) + "connection successful answered")
                            output_json["status"] = self.DOIPStatusCodes.get_code()
                        await self.handleOutputMessage(output_json)
            if output_json == None:
                self.DOIPStatusCodes.set_code("other") #TODO: find better return code
                self.LogMsg.info(str(self.client_address) + " connection not successful")
                output_json = {}
#################
# Output Processing
#################
            if "status" in output_json and output_json["status"] != "EOF":
                await self.handleOutputMessage(output_json) 
    
#################
# End of input loop by EOF
# End of handle method 
#################

    async def handleInputMessage(self):
        """
        Gets the first segment from input and returns the json element in this segment.
        The rfile stays open with pointer on the first line after the '#' delimiter.
        The other segments are handled by the output handle in self.handleOutputMessage().

        @return service type string:  service type identifier
        @return jdata type json:  json element in first segment 
        """
        # now listen to client
        segment_1st, lastLine = await self.DOIPRequest.getLeadingJsonSegment()
        if lastLine == b'':
            return None, None, lastLine
        jdata = self.DOIPRequest._segment_to_json(segment_1st)
        available, service = self.DOIPRequest._get_service_from_leading_json(jdata)
        if not available:
            service = None
        return service, jdata, lastLine
    

    async def handleOperationOnFurtherSegments(self, json_input, service, lastLine):
        """
        The rfile stays open with pointer on the first line after the '#' delimiter.
        The other segments are handled by the output handle in self.handleOutputMessage().

        @return output_data type array of streams: output of service
        """
        output_json = await self.operations.operateService(service, json_input, lastLine, self.rfile, self.client_address)
        return output_json
        
    async def handleOutputMessage(self, output_json):
        DOIPResponse = OutputMessageProcessing(self, output_json, self.wfile)
        await DOIPResponse.respond()

##########################

class DOIPServerOperations():

    status = status_codes()

    def __init__(self):
        # dummy, superseded by implementation class
        pass

    def set_server(self, server):
        self.server = server # relates server to ServerOperations

    async def operateService(self, service, jsondata, lastLine, inDOIPMessage, peer_address):
        pass

    def operate_Hello(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :
        pass

    def operate_Create(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :        
        pass

    def operate_Retrieve(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :
        pass

    def operate_Update(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :
        pass

    def operate_Delete(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :        
        pass

    def operate_Search(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :
        pass
    
    def operate_ListOperations(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :
        pass

    def operate_Other(self, service, jsondata, lastLine, inDOIPMessage, peer_address) :
        pass

    async def get_FurtherSegments(self, lastLine, inDOIPMessage, peer_address):
        """
        returns the following segment in DOIP format of a DOIP request 
        as array of lines of the leading segment. 
        The stream pointer in inDOIPMessage stops at the last position.

        @return input_array type array: lines of leading segment 
        """
        input_array = []
        if  lastLine.startswith(b'@'):
            byte_input, success = self.get_bytes_segment(inDOIPMessage,lastLine)
            if success:
                input_array.append(byte_input.decode())
        byte_input = b''
        terminator_on_last_line = True
        last_line_empty = False
        # input_steam_terminated = False
        while True:
            try:
                line = await inDOIPMessage.readline()
                # print ("in get_FurtherSegments ",line, len(line))
                if line[:-1] == b'':
                    self.LogMsg.info(str(peer_address) + " input terminated while reading segments")
                    break # return input_array
                elif line[:-1] == b'\n':
                    if last_line_empty:
                        self.LogMsg.info(str(peer_address) + " empty lines are invalid inputs")
                        break
                    else:
                        last_line_empty = True
                elif line[:-1] == b'#':
                    # print ("terminator", line, terminator_on_last_line)
                    if terminator_on_last_line:
                        self.LogMsg.debug(str(peer_address) + " input terminated with #")
                        break
                    else:
                        terminator_on_last_line = True
                        input_array.append(byte_input.decode())
                        byte_input = b''
                elif line.startswith(b'@'):
                    byte_input, success = await self.get_bytes_segment(inDOIPMessage,lastLine)
                    if success:
                        input_array.append(byte_input.decode())
                    byte_input = b''
                else:
                    byte_input += line[:-1]
                    terminator_on_last_line = False
            except BrokenPipeError:
                self.LogMsg.error(str(peer_address) + " broken pipe while reading segments")
                self.request_handler.DOIPstatus.set_code("other")
        # print ("returned with input", input_array)
        return input_array

    async def get_bytes_segment(self,inDOIPMessage,lastLine, peer_address):
        """
        From DOIP-Specification:
        a bytes segment, which contains arbitrary bytes. 
        A bytes segment must begin with a single line of text starting with the at-sign character ("@") optionally followed by whitespace terminated by a newline; this line is followed by the bytes in a chunked encoding, which consists of zero or more chunks. 
        Each chunk has:
        - a line of text starting with the UTF-8 representation of a positive decimal number (the size of the chunk excluding the delimiters), optionally followed by whitespace, and terminated by a newline character;
        - as many bytes as indicated by the size, optionally followed by whitespace, and followed by a newline character; or
"
        """

        success = True
        byte_input = b''
        if len(lastLine) > 1:
            numBytes = lastLine.replace(b'@',b'').decode()
            try:
                numBytes = int( numBytes )
                byte_input = await inDOIPMessage.read(numBytes)
                # print ("@>>", lastLine, numBytes, byte_input )
            except:
                self.LogMsg.error(str(peer_address) + " string following @ in '" + lastLine.encode() + "' is not an integer")
                self.request_handler.DOIPstatus.set_code("other")
                success = False
        else:
            last_line_empty = False
            while True:
                try:
                    line = await inDOIPMessage.readline()
                    line = line[:-1]
                    # print (">>",byte_input, line)
                    if line == b'#':
                        # print ("terminator", line)
                        break
                    elif line == b'':
                        if last_line_empty:
                            break
                        else:
                            last_line_empty = True
                    else:
                        byte_input += line
                except BrokenPipeError:
                    self.LogMsg.error(str(peer_address) + " broken pipe while reading 1st segment")
                    self.request_handler.DOIPstatus.set_code("other")
                    success = False
        return byte_input, success

                
