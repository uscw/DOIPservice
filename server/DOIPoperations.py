'''
Created on 11.05.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''

class DOIPServerOperations():

    def __init__(self):
        # dummy, superseded by implementation class
        pass

    def set_server(self, server):
        self.server = server # relates server to ServerOperations

    async def operateService(self, service, jsondata, lastLine, inDOIPMessage, peer_address, requestId):
        operation = service.split("@")[0]
        self.client_address = peer_address
        ret = {}
        if operation == "0.DOIP/Op.Hello" :
            ret = await self.operate_Hello(service, jsondata, lastLine, inDOIPMessage, requestId)
        elif operation == "0.DOIP/Op.Create" : 
            ret = await self.operate_Create(service, jsondata, lastLine, inDOIPMessage, requestId)
        elif operation == "0.DOIP/Op.Retrieve" : 
            ret = await self.operate_Retrieve(service, jsondata, lastLine, inDOIPMessage, requestId)
        elif operation == "0.DOIP/Op.Update" : 
            ret = await self.operate_Update(service, jsondata, lastLine, inDOIPMessage, requestId)
        elif operation == "0.DOIP/Op.Delete" : 
            ret = await self.operate_Delete(service, jsondata, lastLine, inDOIPMessage, requestId)
        elif operation == "0.DOIP/Op.Search" : 
            ret = await self.operate_Search(service, jsondata, lastLine, inDOIPMessage, requestId)
        elif operation == "0.DOIP/Op.ListOperations" : 
            ret = await self.operate_ListOperations(service, jsondata, lastLine, inDOIPMessage, requestId)
        elif "0.DOIP/Op." in operation : 
            ret = await self.operate_Other(service, jsondata, lastLine, inDOIPMessage, requestId)
        else:
            ret = await self.operate_Other(service, jsondata, lastLine, inDOIPMessage, requestId)
        return ret

    def operate_Hello(self, service, jsondata, lastLine, inDOIPMessage, requestId) :
        pass

    def operate_Create(self, service, jsondata, lastLine, inDOIPMessage, requestId) :        
        pass

    def operate_Retrieve(self, service, jsondata, lastLine, inDOIPMessage, requestId) :
        pass

    def operate_Update(self, service, jsondata, lastLine, inDOIPMessage, requestId) :
        pass

    def operate_Delete(self, service, jsondata, lastLine, inDOIPMessage, requestId) :        
        pass

    def operate_Search(self, service, jsondata, lastLine, inDOIPMessage, requestId) :
        pass
    
    def operate_ListOperations(self, service, jsondata, lastLine, inDOIPMessage, requestId) :
        pass

    def operate_Other(self, service, jsondata, lastLine, inDOIPMessage, requestId) :
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
            byte_input, success = await self.get_bytes_segment(inDOIPMessage,lastLine, peer_address)
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
                    byte_input, success = await self.get_bytes_segment(inDOIPMessage, line, peer_address)
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
                byte_input = await inDOIPMessage.read(numBytes)
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
