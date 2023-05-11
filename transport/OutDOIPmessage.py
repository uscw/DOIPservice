'''
Created on 11.05.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
import logging

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
        
    def __init__(self, request_handler, json_response, outsegments=None):
        self.request_handler = request_handler
        self.json_response = json_response
        self.outsegments = outsegments
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
        response_encoded += self._generate_output_segments()
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
            

    def _generate_output_segments(self):
        """
        dummy for generating output sections from the outfile buffer
        
        @return output_data type string: output sections 
        """
        if self.outsegments == None:
            self.output_data = ("#" + "\n").encode()
        else:
            for item in self.outsegments:
                if isinstance(item,bytes):
                    self.output_data += item
                else:
                    self.output_data += item.encode()
                self.output_data += ("#" + "\n").encode()
        return self.output_data