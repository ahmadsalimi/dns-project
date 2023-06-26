from functools import cached_property
from typing import Iterator

import grpc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_parameters
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

from messenger.api.v1 import messenger_pb2 as m
from messenger.api.v1.messenger_pb2_grpc import MessengerServiceServicer, add_MessengerServiceServicer_to_server
from messenger.models import Configuration, ServerKey, Session
from messenger.utils import num2bytes, sha256_hash, sign_message, decrypt_rsa, parse_typed_message, decrypt_aes, \
    isoftype


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

    def GetRSAPublicKey(self, request: m.GetRSAPublicKeyRequest,
                        context: grpc.ServicerContext) -> m.GetRSAPublicKeyResponse:
        return m.GetRSAPublicKeyResponse(key=self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex())

    def GetDHParameters(self, request: m.GetDHParametersRequest,
                        context: grpc.ServicerContext) -> m.SignedMessage:
        return sign_message(m.GetDHParametersResponse(
            p=num2bytes(self.dh_parameters.parameter_numbers().p).hex(),
            g=self.dh_parameters.parameter_numbers().g,
            q=num2bytes(self.dh_parameters.parameter_numbers().q).hex()
            if self.dh_parameters.parameter_numbers().q else None,
        ), self.rsa_private_key)

    def GetDHPublicKey(self, request: m.GetDHPublicKeyRequest,
                       context: grpc.ServicerContext) -> m.SignedMessage:
        return sign_message(m.GetDHPublicKeyResponse(y=num2bytes(self.dh_public_key.public_numbers().y).hex()),
                            self.rsa_private_key)

    def Register(self, request: m.RegisterRequest,
                 context: grpc.ServicerContext) -> m.RegisterResponse:
        id_ = request.id
        password = decrypt_rsa(bytes.fromhex(request.password_ciphertext), self.rsa_private_key).decode()
        form = UserCreationForm(dict(
            username=id_,
            password1=password,
            password2=password,
        ))
        if not form.is_valid():
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, form.errors.as_text())
        form.save()
        return m.RegisterResponse()

    def StartSession(self, request_iterator: Iterator[m.TypedMessage],
                     context: grpc.ServicerContext) -> Iterator[m.SignedMessage]:
        m1 = next(request_iterator)
        if not isoftype(m1, m.LoginRequest):
            context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                          f'Expected {m.LoginRequest.DESCRIPTOR.name}, got {m1.type}')
        login_request = parse_typed_message(m1)
        id_ = login_request.id
        dh_public_key_y = int.from_bytes(bytes.fromhex(login_request.dh_public_key_y), 'big')
        dh_public_key = dh.DHPublicNumbers(y=dh_public_key_y,
                                           parameter_numbers=self.dh_parameters.parameter_numbers()) \
            .public_key(default_backend())
        dh_shared_secret = sha256_hash(self.dh_private_key.exchange(dh_public_key))
        password = decrypt_aes(bytes.fromhex(login_request.password_ciphertext), dh_shared_secret).decode()
        form = AuthenticationForm(None, dict(
            username=id_,
            password=password,
        ))
        if not form.is_valid():
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, form.errors.as_text())
        user = form.get_user()
        session = Session.objects.create(
            user=user,
            dh_public_key=dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            dh_shared_secret=dh_shared_secret,
        )
        try:
            yield sign_message(m.LoginResponse(), self.rsa_private_key, dh_shared_secret)
            for message in request_iterator:
                if isoftype(message, m.EchoMessage):
                    message.value = decrypt_aes(message.value, dh_shared_secret)
                    echo_message = parse_typed_message(message)
                    yield sign_message(m.EchoMessage(message=echo_message.message), self.rsa_private_key,
                                       dh_shared_secret)
                elif isoftype(message, m.ListOnlineUsersRequest):
                    yield sign_message(m.ListOnlineUsersResponse(
                        user_ids=[s.user.username for s in Session.objects.all()]
                    ), self.rsa_private_key, dh_shared_secret)
        finally:
            session.delete()


def grpc_handlers(server):
    add_MessengerServiceServicer_to_server(MessengerService(), server)
