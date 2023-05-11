'''
Created on 11.05.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
import logging
import asyncio
#from DOIPutils import DOIPconfiguration
from server import DOIPserver_implementation_xmpl
from server import DOIPserver as DOIPss
import DOIPutils.DOIPconfiguration as DOIPconfiguration

########## module_xmpl_main function ###########           
def main():
    """
    This is the server. It handles the sockets. It passes requests to the
    listener (the second argument). The server will run in its own thread
    so that we can kill it when we need to.
    """
    LogMsg = logging.getLogger('module_xmpl_main server')
    operations = DOIPserver_implementation_xmpl.DOIPServerOperationsImplementation()
    server_config = DOIPconfiguration.DOIPConfig(config_path = default_dir, config_file = "srv.cfg")
    AuthMethods = DOIPserver_implementation_xmpl.DOIPServerAuthMethodsImplementation(server_config)
    server = DOIPss.asyncioRequestHandler(server_config, operations, AuthMethods)
    operations.set_server(server)
    LogMsg.debug("start server")
    asyncio.run(server.start_server())
    
########## module_xmpl_main section ###########           
if __name__ == '__main__':
    default_dir = "/home/uschwar1/ownCloud/AC/python/xmpls/DOIP_socketserver_disabled/"
    main()
    
# call Op.Hello with:
# { "operationId" : "0.DOIP/Op.Hello", "targetId" : "20.500.123/service" }
#
#
# test with openssl s_client -connect localhost:8493
# port depends on config file
