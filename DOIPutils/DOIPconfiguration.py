'''
Created on 11.05.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
import ssl
import logging
import json

class DOIPConfig():

    def __init__(self,
                 service_ids = {
                     "20.500.123/service" : [
                         "0.DOIP/Op.Hello",
                         "0.DOIP/Op.Create",
                         "0.DOIP/Op.Retrieve",
                         "0.DOIP/Op.Update",
                         "0.DOIP/Op.Delete",
                         "0.DOIP/Op.Search",
                         "0.DOIP/Op.ListOperations"
                     ]
                 },
                 listen_addr = "127.0.0.1",
                 listen_port = 8443,
                 server_cert = "certs/server.crt",
                 server_key =  "certs/server.key",
                 client_cert = "certs/clients.txt",
                 request_queue_size = 10,
                 daemon_threads = True,
                 allow_reuse_address = True,
                 config_file = None,
                 config_path = None,
                 context_verify_mode = ssl.CERT_OPTIONAL
    ):
        """
        DOIP Server Configuration with optional parameters to override default values.
        If a config file is given, this will be used to override the default values.

        @param service_ids         type list of string: allowed service identifier
        @param listen_addr         type string: address where server listens
        @param listen_port         type int: port where server listens
        @param server_cert         type string: file of server certificate
        @param server_key          type string: file of server private key
        @param client_cert         type string: file of allowed client certificates
        @param request_queue_size  type int: size of request queue
        @param daemon_threads      type boolean: daemon threads allowed
        @param allow_reuse_address type boolean: reuse of address allowed
        @param config_path         type string: path to configuration and cert files
        @param config_file         type string: name of configuration file
        @param context_verify_mode type ssl-type: kind of verification mode
        """
        self.LogMsg = logging.getLogger('DOIPConfig')
        self.service_ids =         service_ids       
        self.listen_addr =         listen_addr        
        self.listen_port =         listen_port        
        self.request_queue_size =  request_queue_size 
        self.daemon_threads =      daemon_threads     
        self.allow_reuse_address = allow_reuse_address
        self.context_verify_mode = context_verify_mode
        self.config_file = config_file
        self.config_path = config_path
        if self.config_path != None and self.config_file != None:
            self.read_config_file(self.config_path + self.config_file)
        self.server_cert = self.config_path + server_cert
        self.server_key =  self.config_path + server_key         
        self.client_cert = self.config_path + client_cert        

            
    def read_config_file(self, config_file):
        """
        read a config file to override the default values.
        Content of file:
        service_ids         type list of string: allowed service identifier
        listen_addr         type string: address where server listens
        listen_port         type int: port where server listens
        server_cert         type string: file of server certificate
        server_key          type string: file of server private key
        client_cert         type string: file of allowed client certificates
        request_queue_size  type int: size of request queue
        daemon_threads      type boolean: daemon threads allowed
        allow_reuse_address type boolean: reuse of address allowed
        context_verify_mode type ssl-type: kind of verification mode

        """        
        fd = open(config_file)
        fdin = ""
        for line in fd.readlines():
            if line.strip()[0] != "#":
                fdin += line.strip()
        cfg = json.loads(fdin)
        try:
            self.service_ids =         cfg["service_ids"]
            self.listen_addr =         cfg["listen_addr"]
            self.listen_port =         cfg["listen_port"]
            self.server_cert =         cfg["server_cert"]
            self.server_key =          cfg["server_key"]
            self.client_cert =         cfg["client_cert"]
            self.request_queue_size =  cfg["request_queue_size"]
            self.daemon_threads =      cfg["daemon_threads"]
            self.allow_reuse_address = cfg["allow_reuse_address"]
            self.allow_unauthenticated_access = cfg["allow_unauthenticated_access"]
            self.context_verify_mode = eval(cfg["context_verify_mode"])
            
        except KeyError as e:
            self.LogMsg.error( str(repr(e)) + " in Config File:" + config_file + " using the Default instead" )
        return
