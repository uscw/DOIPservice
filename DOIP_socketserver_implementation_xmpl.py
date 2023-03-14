import sys
import json
import logging
import asyncio
import DOIP_socketserver as DOIPss

default_target = "20.500.123/service"
default_dir = "/home/uschwar1/ownCloud/AC/python/xmpls/DOIP_socketserver/"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    stream=sys.stderr,
)

class DOIPServerOperationsImplementation(DOIPss.DOIPServerOperations):

    def __init__(self):
        self.LogMsg = logging.getLogger('DOIPServerOperationsImplementation')
        self.status = DOIPss.status_codes()

    async def operateService(self, service, jsondata, lastLine, inDOIPMessage, peer_address):
        operation = service.split("@")[0]
        target = service.split("@")[1]
        self.client_address = peer_address
        ret = {}
        if target == default_target:
            if operation == "0.DOIP/Op.Hello" :
                ret = await self.operate_Hello(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Create" : 
                ret = await self.operate_Create(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Retrieve" : 
                ret = await self.operate_Retrieve(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Update" : 
                ret = await self.operate_Update(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Delete" : 
                ret = await self.operate_Delete(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.Search" : 
                ret = await self.operate_Search(service, jsondata, lastLine, inDOIPMessage)
            elif operation == "0.DOIP/Op.ListOperations" : 
                ret = await self.operate_ListOperations(service, jsondata, lastLine, inDOIPMessage)
            elif "0.DOIP/Op." in operation : 
                ret = await self.operate_Other(service, jsondata, lastLine, inDOIPMessage)
            else:
                ret = None
        return ret

    async def operate_Hello(self, service, jsondata, lastLine, inDOIPMessage) :
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
        output_json["input_data"] = await self.get_FurtherSegments(lastLine, inDOIPMessage, self.client_address)
        self.LogMsg.debug(str(self.client_address) + " output from 0.DOIP/Op.Hello: " + str(output_json))
        return output_json

    async def operate_Create(self, service, jsondata, lastLine, inDOIPMessage) :        
        ret = {}
        await asyncio.sleep(0)
        return ret
 
    async def operate_Retrieve(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        await asyncio.sleep(0)
        return ret

    async def operate_Update(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        await asyncio.sleep(0)
        return ret

    async def operate_Delete(self, service, jsondata, lastLine, inDOIPMessage) :        
        ret = {}
        await asyncio.sleep(0)
        return ret

    async def operate_Search(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        await asyncio.sleep(0)
        return ret
    
    async def operate_ListOperations(self, service, jsondata, lastLine, inDOIPMessage) :
        target = service.split("@")[1]
        output = []
        try:
            for item in self.server.config.service_ids[target]:
                output.append(item.split("@")[0])
        except:
            None
        output_json = {}
        output_json["status"] = self.status.codes["success"]
        output_json["output"] = output 
        output_json["input_data"] = await self.get_FurtherSegments(lastLine, inDOIPMessage, self.client_address)
        self.LogMsg.debug(str(self.client_address) + " output from 0.DOIP/Op.Hello: " + str(output_json))
        return output_json

    async def operate_Other(self, service, jsondata, lastLine, inDOIPMessage) :
        ret = {}
        await asyncio.sleep(0)
        return ret
       

########## main function ###########           
def main():
    """_x
    This is the server. It handles the sockets. It passes requests to the
    listener (the second argument). The server will run in its own thread
    so that we can kill it when we need to.
    bind_and_activate=False can optionally be given in DOIPRequestServer instance
    """
    operations = DOIPServerOperationsImplementation()
    server_config = DOIPss.DOIPServerConfig(config_file = default_dir + "srv.cfg")
    server = DOIPss.asyncioRequestHandler(server_config, operations)
    operations.set_server(server)
    asyncio.run(server.start_server())
    
########## main section ###########           
if __name__ == '__main__':
    if (len(sys.argv) == 2):
        default_target = sys.argv[1]
    main()
    
# call Op.Hello with:
# { "operationId" : "0.DOIP/Op.Hello", "targetId" : "20.500.123/service" }
#
#
# test with openssl s_client -connect localhost:8493
# port depends on config file
