import queue
import threading
import uuid
from datetime import datetime
from functools import cached_property
from typing import Iterator, Optional

from google.protobuf.message import Message
from google.protobuf.timestamp_pb2 import Timestamp
import grpc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_parameters
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User

from messenger.api.v1 import messenger_pb2 as m
from messenger.api.v1.messenger_pb2_grpc import MessengerServiceServicer, add_MessengerServiceServicer_to_server
from messenger.models import Configuration, ServerKey, Session, ChatRequest, GroupChat, GroupChatMember, Request
from messenger.utils import num2bytes, sha256_hash, sign_message, decrypt_rsa, parse_typed_message, decrypt_aes, \
    isoftype, sha256_hmac


class MessengerService(MessengerServiceServicer):
    SERVER_RSA_PRV_KEY_NAME = 'server_rsa_prv_key'
    DH_PARAMETERS_NAME = 'dh_parameters'
    SERVER_DH_PRV_KEY_NAME = 'server_dh_prv_key'

    def __init__(self):
        self.__lock = threading.Lock()
        self.__response_queues = {}

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

    @staticmethod
    def __log_request(request: m.TypedMessage, requester: User,
                      context: grpc.ServicerContext):
        if Request.objects.filter(id=request.request_id).exists():
            context.abort(grpc.StatusCode.ALREADY_EXISTS, 'Duplicate request ID')
        Request.objects.create(id=request.request_id,
                               requester=requester,
                               request_type=request.type)

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
        self.__log_request(m1, user, context)
        session = Session.objects.create(
            user=user,
            dh_public_key=dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            dh_shared_secret=dh_shared_secret,
        )
        self.__response_queues[user.username] = response_queue = queue.Queue()
        handle_session_requests_thread = threading.Thread(
            target=self.__handle_session_requests,
            args=(request_iterator, context, response_queue, dh_shared_secret, user),
        )
        handle_session_requests_thread.start()
        print(f'User {user.username} started session')
        try:
            yield sign_message(m.LoginResponse(), self.rsa_private_key, dh_shared_secret)
            print(f'Notifying {user.username}\'s peer users in groups')
            for group in GroupChat.objects.filter(members=user):
                print(f'Notifying {user.username}\'s peer users in group {group.id}')
                for other_session in Session.objects.filter(user__in=group.members.all()).exclude(user=user):
                    print(f'Notifying {other_session.user.username} of {user.username}\'s session')
                    request_id = str(uuid.uuid4())
                    self.__response_queues[other_session.user.username].put((
                        request_id,
                        m.AddNewGroupMemberNotification(
                            group_id=group.id,
                            user_id=user.username,
                        ),
                    ))
            yield sign_message(m.SessionReadyNotification(), self.rsa_private_key, dh_shared_secret)
            while (response := response_queue.get()) and response[1] is not None:
                signed_message = sign_message(response[1], self.rsa_private_key, dh_shared_secret)
                print(f'message {response[0]} of type {signed_message.message.type} signed.')
                signed_message.message.request_id = response[0]
                yield signed_message
                print(f'message {response[0]} of type {signed_message.message.type} sent.')
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise e
        finally:
            print(f'Notifying {user.username}\'s peer users in groups to remove them')
            for group in GroupChat.objects.filter(members=user):
                print(f'Notifying {user.username}\'s peer users in group {group.id} to remove them')
                for other_session in Session.objects.filter(user__in=group.members.all()).exclude(user=user):
                    print(f'Notifying {other_session.user.username} of {user.username}\'s session to remove them')
                    request_id = str(uuid.uuid4())
                    self.__response_queues[other_session.user.username].put((
                        request_id,
                        m.RemoveGroupMemberNotification(
                            group_id=group.id,
                            user_id=user.username,
                        ),
                    ))
            session.delete()

    def __handle_session_requests(self, request_iterator: Iterator[m.TypedMessage],
                                  context: grpc.ServicerContext,
                                  response_queue: queue.Queue,
                                  dh_shared_secret: bytes,
                                  user: User) -> None:
        try:
            for message in request_iterator:
                self.__log_request(message, user, context)
                request_id = message.request_id
                print(f'request id: {request_id}')
                message.value = decrypt_aes(message.value, dh_shared_secret)
                if sha256_hmac(dh_shared_secret, message.value).hex() != message.mac:
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'HMAC verification failed')
                request = parse_typed_message(message)
                print('request parsed')
                response = self.__handle_session_request(request_id, request, user)
                print('response handled')
                if response is None:
                    continue
                response_queue.put((request_id, response))
        except Exception as e:
            import traceback
            traceback.print_exc()
            raise e
        finally:
            response_queue.put((None, None))

    # noinspection PyUnresolvedReferences
    def __handle_session_request(self, request_id: str, request: Message,
                                 user: User) -> Optional[Message]:
        if request.DESCRIPTOR.name == m.EchoMessage.DESCRIPTOR.name:
            return m.EchoMessage(message=request.message)
        elif request.DESCRIPTOR.name == m.ListOnlineUsersRequest.DESCRIPTOR.name:
            return m.ListOnlineUsersResponse(user_ids=[s.user.username for s in Session.objects.all()])
        elif request.DESCRIPTOR.name == m.ChatRequestFromClient.DESCRIPTOR.name:
            # user = requester
            if user.username == request.requestee:
                return m.ChatRequestFromClientResponse(
                    accepted=False,
                    error='Cannot send a chat request to yourself',
                )
            if not Session.objects.filter(user__username=request.requestee).exists():
                return m.ChatRequestFromClientResponse(
                    accepted=False,
                    error=f'User {request.requestee} either does not exist or is offline',
                )
            ChatRequest.objects.create(
                id=uuid.UUID(request_id),
                requester=user,
                requestee=User.objects.get(username=request.requestee),
            )
            self.__response_queues[request.requestee].put((request_id, m.ChatRequestFromServer(
                requester=user.username,
                dh_public_key_y=num2bytes(user.session.parsed_dh_public_key.public_numbers().y).hex(),
            )))
            return
        elif request.DESCRIPTOR.name == m.ChatRequestFromServerResponse.DESCRIPTOR.name:
            # user = requestee
            if not ChatRequest.objects.filter(id=request_id).exists():
                return
            chat_request = ChatRequest.objects.get(id=request_id)
            if chat_request.requestee != user:
                return
            if not request.accepted:
                self.__response_queues[chat_request.requester.username].put((request_id, m.ChatRequestFromClientResponse(
                    accepted=False,
                    error=f'User {user.username} rejected your chat request',
                )))
                chat_request.status = ChatRequest.Status.REJECTED
                chat_request.save()
                return
            self.__response_queues[chat_request.requester.username].put((request_id, m.ChatRequestFromClientResponse(
                accepted=True,
                dh_public_key_y=num2bytes(user.session.parsed_dh_public_key.public_numbers().y).hex(),
            )))
            chat_request.status = ChatRequest.Status.ACCEPTED
            chat_request.save()
            return
        elif request.DESCRIPTOR.name == m.ChatMessageToServer.DESCRIPTOR.name:
            if not ChatRequest.objects.filter(requester__username__in=[user.username, request.destination],
                                              requestee__username__in=[user.username, request.destination],
                                              status=ChatRequest.Status.ACCEPTED).exists():
                return m.ChatMessageResponse(
                    successful=False,
                    error='No accepted chat request between the two users',
                )
            now = datetime.now()
            timestamp = Timestamp()
            timestamp.FromDatetime(now)
            self.__response_queues[request.destination].put((request_id, m.ChatMessageToClient(
                source=user.username,
                timestamp=timestamp,
                message_ciphertext=request.message_ciphertext,
            )))
            return m.ChatMessageResponse(
                successful=True,
                timestamp=timestamp,
            )
        elif request.DESCRIPTOR.name == m.RefreshDHKeyRequestToServer.DESCRIPTOR.name:
            user.session.parsed_dh_public_key = dh.DHPublicNumbers(
                y=int.from_bytes(bytes.fromhex(request.dh_public_key_y), 'big'),
                parameter_numbers=self.dh_parameters.parameter_numbers(),
            ).public_key(default_backend())

            user.session.dh_shared_secret = sha256_hash(
                self.dh_private_key.exchange(user.session.parsed_dh_public_key))
            user.session.save()

            # other users
            for session in Session.objects.exclude(user=user):
                self.__response_queues[session.user.username].put((request_id, m.RefreshDHKeyRequestToClient(
                    requester=user.username,
                    dh_public_key_y=request.dh_public_key_y,
                )))
            return
        elif request.DESCRIPTOR.name == m.CreateGroupRequest.DESCRIPTOR.name:
            if GroupChat.objects.filter(id=request.id).exists():
                return m.CreateGroupResponse(
                    successful=False,
                    error=f'Group with id {request.id} already exists',
                )
            group_chat = GroupChat.objects.create(id=request.id)
            GroupChatMember.objects.create(
                user=user,
                group_chat=group_chat,
                is_admin=True,
            )
            return m.CreateGroupResponse(
                successful=True,
            )
        elif request.DESCRIPTOR.name == m.ListGroupsRequest.DESCRIPTOR.name:
            print(f'{user.username} requested groups list')
            return m.ListGroupsResponse(
                groups=[
                    m.Group(
                        id=group_chat.id,
                        members=[member.username for member in group_chat.members.all()
                                 if Session.objects.filter(user=member).exists()],
                        is_requester_admin=GroupChatMember.objects.get(user=user, group_chat=group_chat).is_admin,
                    )
                    for group_chat in GroupChat.objects.filter(members=user)
                ]
            )
        elif request.DESCRIPTOR.name == m.GetPublicKeyRequest.DESCRIPTOR.name:
            if not Session.objects.filter(user__username=request.user_id).exists():
                return m.GetPublicKeyResponse(
                    successful=False,
                    error=f'User {request.user_id} either does not exist or is offline',
                )
            return m.GetPublicKeyResponse(
                successful=True,
                dh_public_key_y=num2bytes(Session.objects.get(user__username=request.user_id)
                                          .parsed_dh_public_key.public_numbers().y).hex(),
            )
        elif request.DESCRIPTOR.name == m.AddGroupMemberRequestToServer.DESCRIPTOR.name:
            if not Session.objects.filter(user__username=request.user_id).exists():
                return m.AddGroupMemberResponse(
                    successful=False,
                    error=f'User {request.user_id} either does not exist or is offline',
                )
            if not GroupChatMember.objects.filter(user=user, group_chat__id=request.group_id, is_admin=True).exists():
                return m.AddGroupMemberResponse(
                    successful=False,
                    error=f'User {user.username} is not an admin of group {request.group_id}',
                )
            group_chat = GroupChat.objects.get(id=request.group_id)
            if GroupChatMember.objects.filter(user__username=request.user_id, group_chat=group_chat).exists():
                return m.AddGroupMemberResponse(
                    successful=False,
                    error=f'User {request.user_id} is already a member of group {request.group_id}',
                )
            GroupChatMember.objects.create(
                user=User.objects.get(username=request.user_id),
                group_chat=group_chat,
                is_admin=False,
            )
            self.__response_queues[request.user_id].put((request_id, m.AddGroupMemberRequestToClient(
                group=m.Group(
                    id=group_chat.id,
                    members=[member.username for member in group_chat.members.all()],
                ),
            )))
            for member in group_chat.members.exclude(username__in=[user.username, request.user_id]):
                self.__response_queues[member.username].put((request_id, m.AddNewGroupMemberNotification(
                    group_id=request.group_id,
                    user_id=request.user_id,
                )))
            return m.AddGroupMemberResponse(
                successful=True,
            )
        elif request.DESCRIPTOR.name == m.GroupChatMessageToServer.DESCRIPTOR.name:
            if not GroupChatMember.objects.filter(user=user, group_chat__id=request.group_id).exists():
                return m.GroupChatMessageResponse(
                    successful=False,
                    error=f'User {user.username} is not a member of group {request.group_id}',
                )
            now = datetime.now()
            timestamp = Timestamp()
            timestamp.FromDatetime(now)
            for message in request.messages:
                if not GroupChatMember.objects.filter(user__username=message.destination,
                                                      group_chat__id=request.group_id).exists():
                    continue
                self.__response_queues[message.destination].put((request_id, m.GroupChatMessageToClient(
                    group_id=request.group_id,
                    message=m.ChatMessageToClient(
                        source=user.username,
                        timestamp=timestamp,
                        message_ciphertext=message.message_ciphertext,
                    ),
                )))
            return m.GroupChatMessageResponse(
                successful=True,
                timestamp=timestamp,
            )
        elif request.DESCRIPTOR.name == m.RemoveMemberFromGroupRequestToServer.DESCRIPTOR.name:
            if request.user_id == user.username:
                return m.RemoveMemberFromGroupResponse(
                    successful=False,
                    error=f'User {request.user_id} cannot remove himself from group {request.group_id}',
                )
            if not User.objects.filter(username=request.user_id).exists():
                return m.RemoveMemberFromGroupResponse(
                    successful=False,
                    error=f'User {request.user_id} does not exist',
                )
            if not GroupChatMember.objects.filter(user=user, group_chat__id=request.group_id, is_admin=True).exists():
                return m.RemoveMemberFromGroupResponse(
                    successful=False,
                    error=f'Either user {user.username} is not an admin of group {request.group_id} '
                          f'or group {request.group_id} does not exist',
                )
            group_chat = GroupChat.objects.get(id=request.group_id)
            if not GroupChatMember.objects.filter(user__username=request.user_id, group_chat=group_chat).exists():
                return m.RemoveMemberFromGroupResponse(
                    successful=False,
                    error=f'User {request.user_id} is not a member of group {request.group_id}',
                )
            GroupChatMember.objects.get(user__username=request.user_id, group_chat=group_chat).delete()
            self.__response_queues[request.user_id].put((request_id, m.RemoveMemberFromGroupRequestToClient(
                group_id=request.group_id,
            )))
            for member in group_chat.members.exclude(username__in=[user.username, request.user_id]):
                self.__response_queues[member.username].put((request_id, m.RemoveGroupMemberNotification(
                    group_id=request.group_id,
                    user_id=request.user_id,
                )))
            return m.RemoveMemberFromGroupResponse(
                successful=True,
            )
        else:
            print(f'Unknown message type: {request.DESCRIPTOR.name}')


def grpc_handlers(server):
    add_MessengerServiceServicer_to_server(MessengerService(), server)
