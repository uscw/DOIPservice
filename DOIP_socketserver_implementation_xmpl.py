import sys
import DOIP_socketserver as DOIPss

class DOIPServerOperationsImplementation(DOIPss.DOIPServerOperations):    
    """
    Derived class for DOIP Server Operation Implementation classes based on 
    its base class DOIPServerOperations. It implements the local operations of the server.
    """

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
        return {}

    def operate_Retrieve(self) :
        return {}

    def operate_Update(self) :
        return {}

    def operate_Delete(self) :        
        return {}

    def operate_Search(self) :
        return {}
    
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

    def operate_Other(self) :
        return {}


########## main function ###########           
def main(server_config):
    """
    This is the server. It handles the sockets. It passes requests to the
    listener (the second argument). The server will run in its own thread
    so that we can kill it when we need to.
    bind_and_activate=False can optionally be given in DOIPRequestServer instance
    """
    server = DOIPss.DOIPRequestServer((server_config.listen_addr,
                                server_config.listen_port),
                               DOIPss.RequestHandler, server_config) 
    server.serve_forever()

########## main section ###########           
if __name__ == '__main__':
    if (len(sys.argv) == 2):
        default_target = sys.argv[1]
    server_config = DOIPss.DOIPServerConfig(config_file = "srv.cfg")
    main(server_config)
