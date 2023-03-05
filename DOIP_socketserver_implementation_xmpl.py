import sys
import json
import DOIP_socketserver as DOIPss

default_target = "20.500.123/service"
default_dir = "/home/uschwar1/ownCloud/AC/python/xmpls/DOIP_socketserver/"

class DOIPServerOperationsImplementation(DOIPss.DOIPServerOperations):

    def __init__(self):
        self.LogMsg = DOIPss.LogMsg(4)
        self.status = DOIPss.status_codes()

    def operateService(self, service, jsondata, lastLine, inDOIPMessage):
        operation = service.split("@")[0]
        target = service.split("@")[1]
        ret = {}
        if target == default_target:
            if operation == "0.DOIP/Op.Hello" :
                ret = self.operate_Hello(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Create" : 
                ret = self.operate_Create(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Retrieve" : 
                ret = self.operate_Retrieve(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Update" : 
                ret = self.operate_Update(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Delete" : 
                ret = self.operate_Delete(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Search" : 
                ret = self.operate_Search(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.ListOperations" : 
                ret = self.operate_ListOperations(service, jsondata, lastLine, inDOIPMessage)
            elif "0.DOIP/Op." in operation : 
                ret = self.operate_Other(service, jsondata, lastLine, inDOIPMessage)
            else:
                ret = None
        return ret

    def operate_Hello(self, service, jsondata, lastLine, inDOIPMessage) :
        attr = {}
        attr["ipAddress"] = self.server.config.listen_addr
        attr["port"] = self.server.config.listen_port
        attr["protocol"] = "TCP"
        attr["protocolVersion"] = "2.0"
        attr["publicKey"] = json.loads(self.server.cert_jwk)
        output = {}
        output["id"] = service
        output["type"] = "0.TYPE/DOIPService"
        output["attributes"] = attr
        output_json = {}
        output_json["status"] = self.status.codes["success"]
        output_json["output"] = output
        output_json["input_data"] = len(self.get_FurtherSegments(lastLine, inDOIPMessage))
        self.wfile = None
        return output_json

    def operate_Create(self, service, jsondata, lastLine, inDOIPMessage) :        
        ret = {}
        return ret
 
    def operate_Retrieve(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        return ret

    def operate_Update(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        return ret

    def operate_Delete(self, service, jsondata, lastLine, inDOIPMessage) :        
        ret = {}
        return ret

    def operate_Search(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        return ret
    
    def operate_ListOperations(self, service, jsondata, lastLine, inDOIPMessage) :
        target = service.split("@")[1]
        output = []
        try:
            for item in self.server.config.service_ids[target]:
                output.append(item.split("@")[0])
        except:
            None
        output_json = {}
        output_json["status"] = None
        output_json["output"] = output 
        self.wfile = None
        return output_json

    def operate_Other(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        return ret
       

########## main function ###########           
def main(server_config):
    """_x
    This is the server. It handles the sockets. It passes requests to the
    listener (the second argument). The server will run in its own thread
    so that we can kill it when we need to.
    bind_and_activate=False can optionally be given in DOIPRequestServer instance
    """
    operations = DOIPServerOperationsImplementation()
    server = DOIPss.DOIPRequestServer(
        DOIPss.RequestHandler,
        server_config,
        operations
    ) 
    server.serve_forever()

########## main section ###########           
if __name__ == '__main__':
    if (len(sys.argv) == 2):
        default_target = sys.argv[1]
    server_config = DOIPss.DOIPServerConfig(config_file = default_dir + "srv.cfg")
    main(server_config)
    
# call Op.Hello with:
# { "operationId" : "0.DOIP/Op.Hello", "targetId" : "20.500.123/service" }
#
#
# test with openssl s_client -connect localhost:8493
# port depends on config file
