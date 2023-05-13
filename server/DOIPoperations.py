'''
Created on 11.05.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
from transport import InDOIPmessage as InDOIPmessage

class DOIPServerOperations():

    def __init__(self):
        pass
    
    def set_server(self, server):
        self.server = server # relates server to ServerOperations
        
    def set_client_address(self, client_address):
        self.client_address = client_address

    async def operateService(self, service, jsondata, lastLine, peer_address, requestId, DOIPrequest):
        operation = service.split("@")[0]
        self.set_client_address(peer_address)
        ret = {}
        if operation == "0.DOIP/Op.Hello" :
            ret = await self.operate_Hello(service, jsondata, lastLine, requestId, DOIPrequest)
        elif operation == "0.DOIP/Op.Create" : 
            ret = await self.operate_Create(service, jsondata, lastLine, requestId, DOIPrequest)
        elif operation == "0.DOIP/Op.Retrieve" : 
            ret = await self.operate_Retrieve(service, jsondata, lastLine, requestId, DOIPrequest)
        elif operation == "0.DOIP/Op.Update" : 
            ret = await self.operate_Update(service, jsondata, lastLine, requestId, DOIPrequest)
        elif operation == "0.DOIP/Op.Delete" : 
            ret = await self.operate_Delete(service, jsondata, lastLine, requestId, DOIPrequest)
        elif operation == "0.DOIP/Op.Search" : 
            ret = await self.operate_Search(service, jsondata, lastLine, requestId, DOIPrequest)
        elif operation == "0.DOIP/Op.ListOperations" : 
            ret = await self.operate_ListOperations(service, jsondata, lastLine, requestId, DOIPrequest)
        elif "0.DOIP/Op." in operation : 
            ret = await self.operate_Other(service, jsondata, lastLine, requestId, DOIPrequest)
        else:
            ret = await self.operate_Other(service, jsondata, lastLine, requestId, DOIPrequest)
        return ret

    def operate_Hello(self, service, jsondata, lastLine, requestId, DOIPrequest) :
        pass

    def operate_Create(self, service, jsondata, lastLine, requestId, DOIPrequest) :        
        pass

    def operate_Retrieve(self, service, jsondata, lastLine, requestId, DOIPrequest) :
        pass

    def operate_Update(self, service, jsondata, lastLine, requestId, DOIPrequest) :
        pass

    def operate_Delete(self, service, jsondata, lastLine, requestId, DOIPrequest) :        
        pass

    def operate_Search(self, service, jsondata, lastLine, requestId, DOIPrequest) :
        pass
    
    def operate_ListOperations(self, service, jsondata, lastLine, requestId, DOIPrequest) :
        pass

    def operate_Other(self, service, jsondata, lastLine, requestId, DOIPrequest) :
        pass
