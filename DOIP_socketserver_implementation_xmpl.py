'''
Created on 06.03.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
import sys
import json
import logging
import asyncio
import DOIP_socketserver as DOIPss
import DOIPlogging as DOIPlog

default_target = "20.500.123/service"
# allowed_targets = [default_target]
default_dir = "/home/uschwar1/ownCloud/AC/python/xmpls/DOIP_socketserver_disabled/"
DOIPlog.config()

class DOIPServerOperationsImplementation(DOIPss.DOIPServerOperations):

    def __init__(self):
        self.LogMsg = logging.getLogger('DOIPServerOperationsImplementation')
        self.status = DOIPss.status_codes()

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
    """
    This is the server. It handles the sockets. It passes requests to the
    listener (the second argument). The server will run in its own thread
    so that we can kill it when we need to.
    bind_and_activate=False can optionally be given in DOIPRequestServer instance
    """
    LogMsg = logging.getLogger('main')
    operations = DOIPServerOperationsImplementation()
    server_config = DOIPss.DOIPServerConfig(config_path = default_dir, config_file = "srv.cfg")
    server = DOIPss.asyncioRequestHandler(server_config, operations)
    operations.set_server(server)
    LogMsg.debug("start server")
    asyncio.run(server.start_server())
    
########## main section ###########           
if __name__ == '__main__':
    main()
    
# call Op.Hello with:
# { "operationId" : "0.DOIP/Op.Hello", "targetId" : "20.500.123/service" }
#
#
# test with openssl s_client -connect localhost:8493
# port depends on config file
