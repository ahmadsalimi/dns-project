from functools import cached_property

import grpc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_parameters

from messenger.api.v1 import messenger_pb2 as m
from messenger.api.v1.messenger_pb2_grpc import MessengerServiceServicer, add_MessengerServiceServicer_to_server
from messenger.models import Configuration, ServerKey
from messenger.utils import num2bytes


class MessengerService(MessengerServiceServicer):
    SERVER_RSA_PRV_KEY_NAME = 'server_rsa_prv_key'
    DH_PARAMETERS_NAME = 'dh_parameters'
    SERVER_DH_PRV_KEY_NAME = 'server_dh_prv_key'

    def ensure_rsa_key(self):
        if ServerKey.exists(self.SERVER_RSA_PRV_KEY_NAME):
            return
        rsa_private_key = rsa.generate_private_key(
            public_exponent=int(Configuration.get('rsa_public_exponent', '65537')),
            key_size=int(Configuration.get('rsa_key_size', '2048')),
            backend=default_backend(),
        )
        ServerKey.set(self.SERVER_RSA_PRV_KEY_NAME, rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    @cached_property
    def rsa_private_key(self) -> rsa.RSAPrivateKey:
        self.ensure_rsa_key()
        return load_pem_private_key(ServerKey.get(self.SERVER_RSA_PRV_KEY_NAME),
                                    password=None,
                                    backend=default_backend())

    @cached_property
    def rsa_public_key(self) -> rsa.RSAPublicKey:
        return self.rsa_private_key.public_key()

    @classmethod
    def ensure_dh_parameters(cls):
        if ServerKey.exists(cls.DH_PARAMETERS_NAME):
            return
        dh_parameters = dh.generate_parameters(
            generator=int(Configuration.get('dh_generator', '2')),
            key_size=int(Configuration.get('dh_key_size', '2048')),
            backend=default_backend(),
        )
        ServerKey.set(cls.DH_PARAMETERS_NAME, dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3,
        ))

    @cached_property
    def dh_parameters(self) -> dh.DHParameters:
        self.ensure_dh_parameters()
        return load_pem_parameters(ServerKey.get(self.DH_PARAMETERS_NAME),
                                   backend=default_backend())

    def ensure_dh_key(self):
        if ServerKey.exists(self.SERVER_DH_PRV_KEY_NAME):
            return
        server_dh_private_key = self.dh_parameters.generate_private_key()
        ServerKey.set(self.SERVER_DH_PRV_KEY_NAME, server_dh_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    @cached_property
    def dh_private_key(self) -> dh.DHPrivateKey:
        self.ensure_dh_key()
        return load_pem_private_key(ServerKey.get(self.SERVER_DH_PRV_KEY_NAME),
                                    password=None,
                                    backend=default_backend())

    @cached_property
    def dh_public_key(self) -> dh.DHPublicKey:
        return self.dh_private_key.public_key()

    def GetPublicKey(self, request: m.GetServerPublicKeyRequest,
                     context: grpc.ServicerContext) -> m.GetServerPublicKeyResponse:
        return m.GetServerPublicKeyResponse(key=self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex())

    def GetDHParameters(self, request: m.GetDHParametersRequest,
                        context: grpc.ServicerContext) -> m.GetDHParametersResponse:
        return m.GetDHParametersResponse(
            p=num2bytes(self.dh_parameters.parameter_numbers().p),
            g=self.dh_parameters.parameter_numbers().g,
            q=num2bytes(self.dh_parameters.parameter_numbers().q)
            if self.dh_parameters.parameter_numbers().q else None,
        )

    def GetDHPublicKey(self, request: m.GetDHPublicKeyRequest,
                       context: grpc.ServicerContext) -> m.GetDHPublicKeyResponse:
        return m.GetDHPublicKeyResponse(y=num2bytes(self.dh_public_key.public_numbers().y))


def grpc_handlers(server):
    add_MessengerServiceServicer_to_server(MessengerService(), server)
