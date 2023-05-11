'''
Created on 11.05.2023

@author: Ulrich Schwardmann, Göttingen
@email: uschwar1@gwdg.de
@license: CC BY-SA
'''
import ssl
import logging
from jwcrypto import jwk

class DOIPServerAuthMethods():
    def __init__(self, config):
        """
        Defines authentication mode, provides authorization and authentication for a DOIPRequestServer

        @param config type configuration of DOIPRequestServer: configuration of server
        """
        self.config = config
        self.LogMsg = logging.getLogger('DOIPServerAuthMethod')
        # setup server context including SSL support
        self.SSL_CONTEXT = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.SSL_CONTEXT.load_cert_chain(certfile=self.config.server_cert, keyfile=self.config.server_key)
        # self.auth = self.auth_methods(self.SSL_CONTEXT, self.config)
        self.client_verification_mode()
        self.cert_jwk = self.get_server_certificate_jwk_json()

    def client_verification_mode(self):
        """
        require special certs for connection with the following SSL parameters:
          CERT_NONE - no certificates from the other side are required (or will be looked at if provided)
          CERT_OPTIONAL - certificates are not required, but if provided will be validated, and if validation fails, the connection will also fail
          CERT_REQUIRED - certificates are required, and will be validated, and if validation fails, the connection will also fail
        also verifies source locations, if cert and key are provided by client, cert needs to be known in srv_cfg.client_cert (authorization)
        """
        self.SSL_CONTEXT.verify_mode = self.config.context_verify_mode # ssl.CERT_OPTIONAL
        self.SSL_CONTEXT.load_verify_locations(cafile=self.config.client_cert)

    def get_authentication(self, request_handler, request_cert, client_address):
        """
        provides the authentication for DOIPRequestServer

        @param request_handler type socketserver.RequestHandler: request handler of DOIPRequestServer: 
        @param request_cert type certificate: peer certificate of request
        @param client_address type string: address of client request
        @return common_name type string: common name if resolved, else None
        """
        common_name = None
        try:
            common_name = self._get_certificate_common_name(request_cert)
            if common_name == None:
                self.LogMsg.debug(str(client_address) + " common_name: " + str(common_name) + " changed to 'unknown_client'")
                common_name = "unknown_client"
        except BrokenPipeError:
            self.LogMsg.error(str(client_address) + " broken pipe during authentication from")
        return common_name
    
    def get_authorization(self, request_handler, common_name, service, client_address):
        """
        provides the authorization for DOIPRequestServer. Here the policies for authorization are implemented (currently service 

        @param request_handler type socketserver.RequestHandler: request handler of DOIPRequestServer
        @param common_name type string: common name if resolved, else None
        @param service type 
        @param client_address type string: address of client request
        @result accepted type boolean: True if accepted
        """
        accepted = self._is_authorized_by_policy(service,common_name)
        # optionally check client certificate with whitelist, disabled here
        if accepted:
            self.LogMsg.info(str(client_address) + " accepting service {} for common_name: {}".format(service, common_name))
        else:
            self.LogMsg.info(str(client_address) + " rejecting service {} for common_name: {}".format(service, common_name))
        return accepted

    def _is_authorized_by_policy(self, service, common_name):
        """
        Here the policies for authorization are implemented for given common name and service

        @param service type string: requested service
        @param common_name type string: requesting common name
        @result accepted type boolean: True if accepted
        """
        accepted = False
        operation = service.split("@")[0]
        target = service.split("@")[1]
        # Authorization policy to be implemented here
        try:
            if target in self.config.service_ids and operation in self.config.service_ids[target]: 
                if operation == "0.DOIP/Op.Hello" or operation == "0.DOIP/Op.ListOperations":
                    accepted = True
                elif (common_name != None and common_name.lower().split("@")[0] == "ulrich"):
                    accepted = True
                else:
                    self.LogMsg.warning("operation " + operation + " not available for common name: " + common_name )
            else:
                self.LogMsg.warning("operation " + operation + "not available at this server for target: " + target )
        except:
            self.LogMsg.error( "for common name: " + common_name + " unavailable target requested: " + target + " target: " + operation)
        return accepted
        
    def _get_certificate_common_name(self, cert):
        if (cert is None):
            return None
        for sub in cert.get("subject", ()):
            for key, value in sub:
                if (key == "commonName"):
                    return value

    def get_server_certificate_jwk_json(self):
        self.this_jwk = jwk.JWK
        fd = open(self.config.server_cert)
        cert = ""
        for line in fd.readlines():
            cert += line
        cert_jwk = self.this_jwk.from_pem(cert.encode())
        return cert_jwk.export()
        