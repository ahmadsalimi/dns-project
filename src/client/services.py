import queue
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Dict, Optional, List, Union, Tuple

from pymojihash import hash_to_emoji
from google.protobuf.message import Message
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import grpc

from messenger.api.v1 import messenger_pb2 as m
from messenger.api.v1.messenger_pb2_grpc import MessengerServiceStub
from messenger.utils import parse_signed_message, encrypt_rsa, encrypt_aes, num2bytes, sha256_hash, decrypt_aes, \
    sign_message


@dataclass
class PeerData:
    id: str
    public_key: dh.DHPublicKey
    shared_secret: bytes

    @classmethod
    def from_public_key_y(cls, name: str,
                          peer_public_key_y: str,
                          parameters: dh.DHParameters,
                          my_private_key: dh.DHPrivateKey):
        peer_public_key = dh.DHPublicNumbers(
            y=int.from_bytes(bytes.fromhex(peer_public_key_y), 'big'),
            parameter_numbers=parameters.parameter_numbers(),
        ).public_key(default_backend())
        shared_secret = sha256_hash(my_private_key.exchange(peer_public_key))
        return cls(name, peer_public_key, shared_secret)

    @classmethod
    def from_public_key(cls, name: str,
                        peer_public_key: dh.DHPublicKey,
                        my_private_key: dh.DHPrivateKey):
        shared_secret = sha256_hash(my_private_key.exchange(peer_public_key))
        return cls(name, peer_public_key, shared_secret)

    def refresh(self, my_private_key: dh.DHPrivateKey, parameters: dh.DHParameters,
                peer_public_key_y: Optional[str] = None):
        if peer_public_key_y:
            self.public_key = dh.DHPublicNumbers(
                y=int.from_bytes(bytes.fromhex(peer_public_key_y), 'big'),
                parameter_numbers=parameters.parameter_numbers(),
            ).public_key(default_backend())
        self.shared_secret = sha256_hash(my_private_key.exchange(self.public_key))

    @property
    def public_key_signature(self) -> str:
        return sha256_hash(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )).hex()

    @property
    def shared_secret_signature(self) -> str:
        return sha256_hash(self.shared_secret).hex()


class GroupChat:

    def __init__(self, session: 'Session', group_id: str):
        self.session = session
        self.group_id = group_id
        self.other_members = set()
        self.__unseen_messages = []
        self.__lock = threading.Lock()
        self.__active = False

    def __enter__(self):
        self.__active = True
        self.__print_messages()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__active = False

    def confirm_add_member(self, user_id: str):
        self.other_members.add(user_id)
        self.session.peer_data[user_id] = PeerData.from_public_key(
            user_id,
            self.session.get_public_key(user_id),
            self.session.client.dh_private_key,
        )

    def confirm_remove_member(self, user_id: str):
        self.other_members.remove(user_id)

    def __get_shared_secret(self, user_id: str) -> bytes:
        return self.session.peer_data[user_id].shared_secret

    def send_message(self, message: str):
        request = m.GroupChatMessageToServer(
            group_id=self.group_id,
            messages=[
                m.ChatMessageToServer(
                    destination=member,
                    message_ciphertext=encrypt_aes(message.encode(), self.__get_shared_secret(member)).hex(),
                )
                for member in self.other_members
            ]
        )
        response = self.session.blocking_request(request)
        if not response.successful:
            raise Exception(response.error)
        date = datetime.fromtimestamp(response.timestamp.seconds + response.timestamp.nanos/1e9)

    def receive_message(self, message: m.ChatMessageToClient):
        message_plaintext = decrypt_aes(bytes.fromhex(message.message_ciphertext),
                                        self.__get_shared_secret(message.source)).decode()
        date = datetime.fromtimestamp(message.timestamp.seconds + message.timestamp.nanos/1e9)
        with self.__lock:
            self.__unseen_messages.append((message_plaintext, message.source, date))
        if self.__active:
            self.__print_messages()

    def get_emoticons(self):
        return {
            member: hash_to_emoji(
                sha256_hash(self.__get_shared_secret(member)).hex(),
                hash_length=4,
                no_flags=True,
            )
            for member in self.other_members
        }

    def __print_messages(self):
        with self.__lock:
            for message, sender, date in sorted(self.__unseen_messages, key=lambda x: x[2]):
                print(f'{date} - {sender}: {message}')
            self.__unseen_messages = []


class AdminGroupChat(GroupChat):

    def add_member(self, user_id: str):
        if user_id in self.other_members:
            raise ValueError(f'User {user_id} is already a member of group {self.group_id}')
        request = m.AddGroupMemberRequestToServer(group_id=self.group_id, user_id=user_id)
        response = self.session.blocking_request(request)
        if not response.successful:
            raise Exception(response.error)
        self.confirm_add_member(user_id)

    def remove_member(self, user_id: str):
        if user_id not in self.other_members:
            raise ValueError(f'User {user_id} is not a member of group {self.group_id}')
        request = m.RemoveMemberFromGroupRequestToServer(group_id=self.group_id, user_id=user_id)
        response = self.session.blocking_request(request)
        if not response.successful:
            raise Exception(response.error)
        self.confirm_remove_member(user_id)


class Chat:

    def __init__(self, session: 'Session', other_user_id: str, public_key_y: str):
        self.session = session
        self.other_user_id = other_user_id
        session.peer_data[other_user_id] = PeerData.from_public_key_y(
            other_user_id,
            public_key_y,
            session.client.dh_parameters,
            session.client.dh_private_key,
        )
        self.__unseen_messages = []
        self.__lock = threading.Lock()
        self.__active = False

    @property
    def __peer_data(self) -> PeerData:
        return self.session.peer_data[self.other_user_id]

    def __enter__(self):
        self.__active = True
        self.__print_messages()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__active = False

    def send_message(self, message: str):
        request = m.ChatMessageToServer(
            destination=self.other_user_id,
            message_ciphertext=encrypt_aes(message.encode(), self.__peer_data.shared_secret).hex(),
        )
        response = self.session.blocking_request(request)
        if not response.successful:
            raise Exception(response.error)

    def __print_messages(self):
        with self.__lock:
            for message, date in sorted(self.__unseen_messages, key=lambda x: x[1]):
                print(f'{date} - {self.other_user_id}: {message}')
            self.__unseen_messages = []

    def receive_message(self, response: m.ChatMessageToClient):
        message = decrypt_aes(bytes.fromhex(response.message_ciphertext), self.__peer_data.shared_secret).decode()
        date = datetime.fromtimestamp(response.timestamp.seconds + response.timestamp.nanos/1e9)
        with self.__lock:
            self.__unseen_messages.append((message, date))
        if self.__active:
            self.__print_messages()

    def get_emoticons(self):
        shared_secret_hash = sha256_hash(self.__peer_data.shared_secret).hex()
        return hash_to_emoji(shared_secret_hash, hash_length=4, no_flags=True)


class Session:

    def __init__(self, client: 'Client'):
        self.client = client
        self.peer_data: Dict[str, PeerData] = {}
        self.__requests_queue = queue.Queue()
        self.__responses_queue = queue.Queue()
        self.user_id = None
        self.__is_logged_in = False
        self.__session_ready_event = threading.Event()
        self.__events = {}
        self.__responses = {}
        self.__event_lock = threading.Lock()
        self.__current_response = None
        self.__chats: Dict[str, Chat] = {}
        self.__current_requestee = None
        self.__group_chats: Dict[str, Union[GroupChat, AdminGroupChat]] = {}
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.__closed = False
        self.reply_attack_protector = ReplyAttackProtector()

    def wait(self):
        self.__session_ready_event.wait()
        self.__sync_group_chats()

    def __iter__(self):
        return self

    def __next__(self):
        try:
            if self.__closed:
                raise StopIteration
            next_: Tuple[str, Message] = self.__requests_queue.get()
            if not next_:
                raise StopIteration
            request_id, request = next_
            signed_message = sign_message(request, self.rsa_private_key,
                                          request_id,
                                          self.client.dh_server_shared_key if self.__is_logged_in else None)
            return signed_message
        except Exception:
            raise StopIteration

    def __push_responses_to_queue(self, response_iterator: Iterator[m.SignedMessage]):
        try:
            for response in response_iterator:
                try:
                    request_id = response.message.request_id
                    self.reply_attack_protector.validate_response(request_id, response.message.type)
                    response = parse_signed_message(response, self.client.server_rsa_public_key,
                                                    self.client.dh_server_shared_key)
                    self.__responses_queue.put((request_id, response))
                except ReplyAttackProtector.Error:
                    pass
        except grpc._channel._MultiThreadedRendezvous as e:
            if e.code() != grpc.StatusCode.CANCELLED:
                print(f'Error: {e}')
            self.close()
            self.__session_ready_event.set()
            for event in self.__events.values():
                event.set()

    def start(self, stub: MessengerServiceStub, id_: str, password: str):
        self.__login(id_, password)
        threading.Thread(target=self.__push_responses_to_queue, args=(stub.StartSession(self),), daemon=True).start()
        while True:
            if self.__closed:
                break
            request_id, response = self.__responses_queue.get()
            if response is None:
                break

            def f():
                if not self.__is_logged_in:
                    if not isinstance(response, m.LoginResponse):
                        self.__responses_queue.put((request_id, response))
                    else:
                        self.__is_logged_in = True
                elif request_id in self.__events:
                    with self.__event_lock:
                        self.__events[request_id].set()
                        self.__responses[request_id] = response
                else:
                    self.__handle_notification(request_id, response)
            threading.Thread(target=f, daemon=True).start()

    # noinspection PyUnresolvedReferences
    def __handle_notification(self, request_id: str, response: Message):
        if isinstance(response, m.SessionReadyNotification):
            self.__session_ready_event.set()
        elif isinstance(response, m.ChatRequestFromServer):
            answer = True
            print(f'Chat request from {response.requester}. Automatically accepting.')
            self.__chats[response.requester] = Chat(self, response.requester, response.dh_public_key_y)
            request = m.ChatRequestFromServerResponse(
                accepted=answer,
            )
            self.__requests_queue.put((request_id, request))
        elif isinstance(response, m.ChatMessageToClient):
            if response.source not in self.__chats:
                return
            self.__chats[response.source].receive_message(response)
        elif isinstance(response, m.RefreshDHKeyRequestToClient):
            if response.requester not in self.peer_data:
                return
            self.peer_data[response.requester].refresh(
                self.client.dh_private_key,
                self.client.dh_parameters,
                response.dh_public_key_y,
            )
        elif isinstance(response, m.AddGroupMemberRequestToClient):
            print(f'Group {response.group.id} added you')
            self.__group_chats[response.group.id] = GroupChat(
                self, response.group.id)
            for member in response.group.members:
                if member == self.user_id:
                    continue
                self.__group_chats[response.group.id].confirm_add_member(member)
        elif isinstance(response, m.AddNewGroupMemberNotification):
            self.__group_chats[response.group_id].confirm_add_member(response.user_id)
        elif isinstance(response, m.RemoveGroupMemberNotification):
            self.__group_chats[response.group_id].confirm_remove_member(response.user_id)
        elif isinstance(response, m.GroupChatMessageToClient):
            self.__group_chats[response.group_id].receive_message(response.message)
        elif isinstance(response, m.RemoveMemberFromGroupRequestToClient):
            print(f'You were removed from group {response.group_id}')
            del self.__group_chats[response.group_id]
        else:
            print(f"Unknown response: {response.DESCRIPTOR.name}")

    def __login(self, id_: str, password: str):
        password_ciphertext = encrypt_aes(password.encode(), self.client.dh_server_shared_key).hex()
        request = m.LoginRequest(
            id=id_,
            password_ciphertext=password_ciphertext,
            dh_public_key_y=num2bytes(self.client.dh_public_key.public_numbers().y).hex(),
            rsa_public_key=self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).hex(),
        )
        self.user_id = id_
        self.__requests_queue.put((str(uuid.uuid4()), request))

    def __sync_group_chats(self):
        request = m.ListGroupsRequest()
        response = self.blocking_request(request)
        self.__group_chats = {
            group.id: GroupChat(self, group.id)
            if not group.is_requester_admin
            else AdminGroupChat(self, group.id)
            for group in response.groups
        }
        for group in response.groups:
            for member in group.members:
                if member == self.user_id:
                    continue
                self.__group_chats[group.id].confirm_add_member(member)

    def async_request(self, request: Message):
        if self.__closed:
            raise RuntimeError('Client is closed')
        request_id = str(uuid.uuid4())
        self.__requests_queue.put((request_id, request))

    def blocking_request(self, request: Message):
        if self.__closed:
            raise RuntimeError('Client is closed')
        request_id = str(uuid.uuid4())
        with self.__event_lock:
            self.__events[request_id] = event = threading.Event()
        self.__requests_queue.put((request_id, request))
        event.wait()
        with self.__event_lock:
            del self.__events[request_id]
            response = self.__responses[request_id]
            del self.__responses[request_id]
        return response

    def close(self):
        self.__closed = True
        self.__requests_queue.put(None)
        self.__responses_queue.put((None, None))

    def echo(self, message: str) -> str:
        response = self.blocking_request(m.EchoMessage(message=message))
        return response.message

    def list_online_users(self):
        request = m.ListOnlineUsersRequest()
        response = self.blocking_request(request)
        return response.user_ids

    def start_chat(self, requestee: str):
        if requestee in self.__chats:
            return self.__chats[requestee]
        request = m.ChatRequestFromClient(requestee=requestee)
        response = self.blocking_request(request)
        if not response.accepted:
            raise Exception(response.error)
        self.__chats[requestee] = Chat(self, requestee, response.dh_public_key_y)
        return self.__chats[requestee]

    def get_chat(self, user_id: str):
        return self.__chats[user_id]

    def list_chats(self):
        return list(self.__chats.keys())

    def refresh_dh_key(self):
        self.client.dh_private_key = self.client.dh_parameters.generate_private_key()
        self.client.dh_public_key = self.client.dh_private_key.public_key()
        request = m.RefreshDHKeyRequestToServer(
            dh_public_key_y=num2bytes(self.client.dh_public_key.public_numbers().y).hex(),
        )
        self.async_request(request)
        for peer in self.peer_data.values():
            peer.refresh(
                self.client.dh_private_key,
                self.client.dh_parameters,
            )

    def create_group(self, id_: str):
        request = m.CreateGroupRequest(id=id_)
        response = self.blocking_request(request)
        if not response.successful:
            raise Exception(response.error)
        self.__group_chats[id_] = AdminGroupChat(self, id_)
        return self.__group_chats[id_]

    def list_my_groups(self) -> List[str]:
        return list(self.__group_chats.keys())

    def get_group_chat(self, group_id: str) -> GroupChat:
        return self.__group_chats[group_id]

    def get_public_key(self, user_id: str) -> dh.DHPublicKey:
        request = m.GetPublicKeyRequest(user_id=user_id)
        response = self.blocking_request(request)
        if not response.successful:
            raise Exception(response.error)
        return dh.DHPublicNumbers(
            y=int.from_bytes(bytes.fromhex(response.dh_public_key_y), 'big'),
            parameter_numbers=self.client.dh_parameters.parameter_numbers(),
        ).public_key(default_backend())


class ReplyAttackProtector:

    class Error(Exception):
        pass

    def __init__(self):
        self.__lock = threading.Lock()
        self.responses = set()

    def validate_response(self, request_id: str, message_type: str):
        with self.__lock:
            if (request_id, message_type) in self.responses:
                raise self.Error('Duplicate response')
            self.responses.add((request_id, message_type))


class Client:

    def __init__(self, server_addr: str):
        self.server_addr = server_addr
        with self.__create_stub() as stub:
            self.server_rsa_public_key = load_pem_public_key(
                bytes.fromhex(stub.GetRSAPublicKey(m.GetRSAPublicKeyRequest()).key),
                default_backend(),
            )
            dh_parameters = parse_signed_message(stub.GetDHParameters(m.GetDHParametersRequest()),
                                                 self.server_rsa_public_key)
            self.dh_parameters = dh.DHParameterNumbers(
                p=int.from_bytes(bytes.fromhex(dh_parameters.p), 'big'),
                g=dh_parameters.g,
                q=int.from_bytes(bytes.fromhex(dh_parameters.q), 'big')
                if dh_parameters.q else None,
            ).parameters(default_backend())
            dh_public_key = parse_signed_message(stub.GetDHPublicKey(m.GetDHPublicKeyRequest()),
                                                 self.server_rsa_public_key)
            self.server_dh_public_key = dh.DHPublicNumbers(
                y=int.from_bytes(bytes.fromhex(dh_public_key.y), 'big'),
                parameter_numbers=self.dh_parameters.parameter_numbers(),
            ).public_key(default_backend())
        self.dh_private_key = self.dh_parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        self.dh_server_shared_key = sha256_hash(self.dh_private_key.exchange(self.server_dh_public_key))
        self.__in_session = False

    @contextmanager
    def __create_stub(self) -> Iterator[MessengerServiceStub]:
        with grpc.insecure_channel(self.server_addr) as channel:
            yield MessengerServiceStub(channel)

    def register(self, id_: str, password: str):
        id_pass_hash = sha256_hash((id_ + password).encode()).hex()
        password_ciphertext = encrypt_rsa((password + id_pass_hash).encode(), self.server_rsa_public_key).hex()
        with self.__create_stub() as stub:
            stub.Register(m.RegisterRequest(
                id=id_,
                password_ciphertext=password_ciphertext,
            ))

    @contextmanager
    def start_session(self, id_: str, password: str) -> Iterator[Session]:
        if self.__in_session:
            raise Exception("Already in session")
        self.__in_session = True
        try:
            with self.__create_stub() as stub:
                session = Session(self)
                session_thread = threading.Thread(
                    target=session.start,
                    args=(stub, id_, password),
                )
                session_thread.start()
                session.wait()

                yield session

                session.close()
                session_thread.join()
        finally:
            self.__in_session = False
