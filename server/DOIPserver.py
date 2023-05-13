'''
Created on 06.03.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
import sys
import logging
import asyncio
import datetime
import DOIPutils.DOIPlogging as DOIPlog
import transport.DOIPstatusCodes
from transport import OutDOIPmessage, InDOIPmessage

#import DOIPio

# default_target = "20.500.123/service"
# default_dir = "/home/uschwar1/ownCloud/AC/python/xmpls/DOIP_socketserver/"
DOIPlog.config()

    
class asyncioRequestHandler():
    def __init__(self, config, operations, auth_methods):
        self.operations = operations
        self.auth_methods = auth_methods
        self.config = config
        self.config_path = self.config.config_path
        self.server_addr = self.config.listen_addr
        self.server_port = self.config.listen_port
        
        # setup server context including SSL support
        # self.SSL_CONTEXT = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # self.SSL_CONTEXT.load_cert_chain(certfile=self.config.server_cert, keyfile=self.config.server_key)
        # self.auth = self.auth_methods(self.SSL_CONTEXT, self.config)
        # self.auth.client_verification_mode()
        # self.cert_jwk = self.auth.get_server_certificate_jwk_json()

        
    async def start_server(self):
        # self.IPaddress = '127.0.0.1'
        # self.port = 10000
        self.LogMsg = logging.getLogger('AsyncIO_RequestHandler')
        try:
            self.server = await asyncio.start_server(self.handle, self.server_addr, self.server_port, ssl=self.auth_methods.SSL_CONTEXT)
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
        self.DOIPStatusCodes = transport.DOIPstatusCodes.status_codes()
        output_json = {}
#################
# authentication
#################
        try:
            self.request_cert = self.rfile._transport.get_extra_info('peercert')
            # print (self.request_cert, self.request.cipher(), self.server.cert_jwk)
        except BrokenPipeError:
            self.LogMsg.error(str(self.client_address) + " broken pipe while getting peer cert")
        cname = self.auth_methods.get_authentication(self, self.request_cert, str(self.client_address))
        if cname == None:
            self.DOIPStatusCodes.set_code("unauthenticated")
            self.LogMsg.error(str(self.client_address) + " request could not be authenticated")
            # output_json = b'{ "status" : self.DOIPStatusCodes.get_code() }'
        else:
            while True:
#################
# Input Processing
#################
                self.DOIPRequest = InDOIPmessage.InputMessageProcessing(self, self.rfile, self.config)
                service, input_json, lastLine = await self.handleInputMessage()
                if lastLine == b'':
                    self.LogMsg.info(str(self.client_address) + " input stream terminated")
                    output_json = { "status" : "EOF" }
                    break
                requestId = self._get_requestId(input_json)
                if input_json == None:
                    self.DOIPStatusCodes.set_code("other")
                    self.LogMsg.info(str(self.client_address) + " no valid JSON input")
                    output_json = { "status" : self.DOIPStatusCodes.get_code(), "requestId" : requestId }
                    await self.handleOutputMessage(output_json)
                elif service == None:
                    self.DOIPStatusCodes.set_code("invalid")
                    self.LogMsg.info(str(self.client_address) + " input invalid")
                    output_json = { "status" : self.DOIPStatusCodes.get_code(), "requestId" : requestId }
                    await self.handleOutputMessage(output_json)
                else:
#################
# authorization
#################
                    accepted = self.auth_methods.get_authorization(self, cname, service, self.client_address)
                    if not accepted:
                        self.DOIPStatusCodes.set_code("unauthorized")
                        self.LogMsg.info(str(self.client_address) + " connection unauthorized")
                        output_json = { "status" : self.DOIPStatusCodes.get_code(), "requestId" : requestId }
                    else:
#################
# Operation
#################
                        output_json = await self.handleOperationOnFurtherSegments(input_json, service, lastLine, requestId)
                        # print ("Operation gives Output: ", output_json, isinstance(output_json,dict),  "status" not in output_json)
                        if output_json != None and isinstance(output_json,dict) and "status" not in output_json:
                            self.DOIPStatusCodes.set_code("success")
                            self.LogMsg.info(str(self.client_address) + "connection successful answered")
                            output_json= { "status" : self.DOIPStatusCodes.get_code(), "requestId" : requestId }
                        await self.handleOutputMessage(output_json)
            if output_json == None:
                self.DOIPStatusCodes.set_code("other") #TODO: find better return code
                self.LogMsg.info(str(self.client_address) + " connection not successful")
                output_json = { "status" : self.DOIPStatusCodes.get_code(), "requestId" : requestId }
#################
# Output Processing
#################
            if "status" in output_json and output_json["status"] != "EOF":
                await self.handleOutputMessage(output_json) 
    
#################
# End of input loop by EOF
# End of handle method 
#################
    def _get_requestId(self,input_json):
        if isinstance(input_json, object):            
            try:
                operationId = input_json["operationId"]
            except: 
                operationId = "noOperationIdFound"
                self.LogMsg.warn(str(self.client_address) + " no operationId found in client request")
            try:
                targetId = input_json["targetId"]
            except:
                targetId = "noTargetIdFound"
                self.LogMsg.warn(str(self.client_address) + " no targetId found in client request")
            try:
                requestId = input_json["requestId"]
            except:
                requestId = "instead_client_reqID#" + self.client_address[0] + ":" + targetId + "?" + operationId + "@" + self.requestInputTime
                self.LogMsg.info(str(self.client_address) + " no requestId found in client request, used instead: " + requestId)
        else:
            requestId = "invalidJsonHeader"
        return requestId   
    
    async def handleInputMessage(self):
        """
        Gets the first segment from input and returns the json element in this segment.
        The rfile stays open with pointer on the first line after the '#' delimiter.
        The other segments are handled by the output handle in self.handleOutputMessage().

        @return service type string:  service type identifier
        @return jdata type json:  json element in first segment 
        """
        # now listen to client
        service = None
        segment_1st, lastLine = await self.DOIPRequest.getLeadingJsonSegment()
        self.requestInputTime = datetime.datetime.utcnow().isoformat()
        if lastLine == b'':
            return None, None, lastLine
        jdata = self.DOIPRequest._segment_to_json(segment_1st)
        if jdata != None:
            service = self.DOIPRequest._get_service_from_leading_json(jdata)
        return service, jdata, lastLine
    

    async def handleOperationOnFurtherSegments(self, input_json, service, lastLine, requestId):
        """
        The rfile stays open with pointer on the first line after the '#' delimiter.
        The other segments are handled by the output handle in self.handleOutputMessage().

        @return output_data type array of streams: output of service
        """
        output_json = await self.operations.operateService(service, input_json, lastLine, self.client_address, requestId, self.DOIPRequest)
        return output_json
        
    async def handleOutputMessage(self, output_json):
        DOIPResponse = OutDOIPmessage.OutputMessageProcessing(self, output_json)
        await DOIPResponse.respond()

