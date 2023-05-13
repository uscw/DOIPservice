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

    if applicable and extracts special elements. 
       If threading is enabled on server using ThreadingMixIn
           - all local variables are independent and thread safe
           - all global variables and variables in for instance self.server = self.request_handler.server are not thread safe and should be written with care
           - all other variables in self.request_handler are independent and thread safe
    """
    def __init__(self, request_handler, inDOIPstream, config):
        self.request_handler = request_handler
        self.inDOIPstream = inDOIPstream
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
                line = await self.inDOIPstream.readline() # skip trailing "\n"
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
    
    async def get_FurtherSegments(self, lastLine):
        """
        returns the following segment in DOIP format of a DOIP request 
        as array of lines of the leading segment. 
        The stream pointer in inDOIPstream stops at the last position.

        @return input_array type array: lines of leading segment 
        """
        try:
            peer_address = self.request_handler.client_address
        except:
            peer_address = ( "server" , "port" )
        input_array = []
        if  lastLine.startswith(b'@'):
            byte_input, success = await self.get_bytes_segment(self.inDOIPstream,lastLine, peer_address)
            if success:
                input_array.append(byte_input.decode())
        byte_input = b''
        terminator_on_last_line = True
        last_line_empty = False
        # input_steam_terminated = False
        while True:
            try:
                line = await self.inDOIPstream.readline()
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
                elif line.startswith(b'#'):
                    # print ("terminator", line, terminator_on_last_line)
                    if terminator_on_last_line:
                        self.LogMsg.debug(str(peer_address) + " input terminated with #")
                        break
                    else:
                        terminator_on_last_line = True
                        input_array.append(byte_input.decode())
                        byte_input = b''
                elif line.startswith(b'@'):
                    byte_input, success = await self.get_bytes_segment(self.inDOIPstream, line, peer_address)
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

    async def get_bytes_segment(self,inDOIPstream,lastLine, peer_address):
        """
        From DOIP-Specification:
        a bytes segment, which contains arbitrary bytes. 
        A bytes segment must begin with a single line of text starting with the 
        at-sign character ("@") optionally followed by whitespace terminated 
        by a newline; 
        this line is followed by the bytes in a chunked encoding, 
        which consists of zero or more chunks. 
        Each chunk has:
        - a line of text starting with the UTF-8 representation of a positive decimal 
          number (the size of the chunk excluding the delimiters), 
          optionally followed by whitespace, and terminated by a newline character;
        - as many bytes as indicated by the size, optionally followed by whitespace, 
          and followed by a newline character; or
        - an empty segment, which indicates the end of the request or response.
        """

        success = True
        byte_input = b''
        if len(lastLine) > 1:
            numBytes = lastLine.replace(b'@',b'').strip().decode()
            try:
                numBytes = int( numBytes )
                byte_input = await inDOIPstream.read(numBytes)
                byte_input = byte_input.decode().split("\n")[0].encode() # truncate if numBytes > EOL
                # print ("@>>", lastLine, numBytes, byte_input )
            except:
                self.LogMsg.error(str(peer_address) + " string following @ in '" + lastLine.encode() + "' is not an integer")
                self.request_handler.DOIPstatus.set_code("other")
                success = False
        else:
            last_line_empty = False
            while True:
                try:
                    line = await inDOIPstream.readline()
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
       