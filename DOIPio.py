import sys
import json
from datetime import datetime
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
        if operation + "@" in self.config.service_ids:
            self.LogMsg.info(peer_address,"service requested: " + operation, Method = " target: " + target + " on this server")
            avail = True
        else:
            self.LogMsg.error(peer_address,"unavailable service requested: " + operation, Method = " target: " + target)
            avail = False
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

