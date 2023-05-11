'''
Created on 11.05.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
import json
import logging
      
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
        input_json = b''
        while True:
            try:
                line = await self.inDOIPMessage.readline() # skip trailing "\n"
                if len(line) == 0: 
                    self.LogMsg.debug(str(peer_address) + " input data stream ends with EOF")                        
                    return input_json, line[:-1] # EOF reached
                elif line[:-1] == b'':
                    self.LogMsg.warn(str(peer_address) + " data stream ends with empty line and without '#' after 1st segment")                        
                    return input_json, line[:-1] # treated as if EOF reached
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
                    input_json += line[:-1]
            except BrokenPipeError:
                self.LogMsg.error(str(peer_address) + " broken pipe while reading 1st segment")
                self.request_handler.DOIPstatus.set_code("other")
        # print ("input_json",input_json)
        return input_json, line[:-1]

    
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
            self.LogMsg.error(str(peer_address) + " JSONDecodeError")
            jdata = None
        return jdata
        
    def _get_service_from_leading_json(self, jdata):
        """
        internal function that tries to get the service id 
        and its availability on this server out of JSON data.

        @param jdata type json.object: input data as json object
        @return service type string: service id
        @return avail type boolean: availability on this server
        """
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
                else:
                    self.LogMsg.error(str(peer_address) + " unavailable service requested: " + operation + ", target: " + target)
            except:
                self.LogMsg.error(str(peer_address) + " unavailable target requested: " + target + ", target: " + operation)
        return service
       