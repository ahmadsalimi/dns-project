from functools import cached_property

import grpc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from messenger.api.v1.greeting_pb2 import GreetingRequest, GreetingResponse
from messenger.api.v1.greeting_pb2_grpc import GreetingServiceServicer, add_GreetingServiceServicer_to_server
from messenger.api.v1.messenger_pb2 import GetServerPublicKeyRequest, GetServerPublicKeyResponse
from messenger.api.v1.messenger_pb2_grpc import MessengerServiceServicer, add_MessengerServiceServicer_to_server
from messenger.models import Configuration


class GreetingService(GreetingServiceServicer):

    def SayHello(self, request: GreetingRequest, context: grpc.ServicerContext) -> GreetingResponse:
        return GreetingResponse(message=f'Hello {request.name}!')


class MessengerService(MessengerServiceServicer):
    SERVER_RSA_PRV_KEY_NAME = 'server_rsa_prv_key'

    def ensure_rsa_key(self):
        if Configuration.exists(self.SERVER_RSA_PRV_KEY_NAME):
            return
        rsa_private_key = rsa.generate_private_key(
            public_exponent=int(Configuration.get('rsa_public_exponent', '65537')),
            key_size=int(Configuration.get('rsa_key_size', '2048')),
            backend=default_backend(),
        )
        Configuration.set(self.SERVER_RSA_PRV_KEY_NAME, rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex())

    @cached_property
    def rsa_private_key(self) -> rsa.RSAPrivateKey:
        self.ensure_rsa_key()
        return load_pem_private_key(bytes.fromhex(Configuration.get(self.SERVER_RSA_PRV_KEY_NAME)),
                                    password=None,
                                    backend=default_backend())

    @cached_property
    def rsa_public_key(self) -> rsa.RSAPublicKey:
        return self.rsa_private_key.public_key()

    def GetPublicKey(self, request: GetServerPublicKeyRequest,
                     context: grpc.ServicerContext) -> GetServerPublicKeyResponse:
        return GetServerPublicKeyResponse(key=self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex())


def grpc_handlers(server):
    add_GreetingServiceServicer_to_server(GreetingService(), server)
    add_MessengerServiceServicer_to_server(MessengerService(), server)
