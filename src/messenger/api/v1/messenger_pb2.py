# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: messenger/api/v1/messenger.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n messenger/api/v1/messenger.proto\x12\x02v1\x1a\x1fgoogle/protobuf/timestamp.proto\"L\n\x0cTypedMessage\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x0c\n\x04type\x18\x02 \x01(\t\x12\r\n\x05value\x18\x03 \x01(\x0c\x12\x0b\n\x03mac\x18\x04 \x01(\t\"E\n\rSignedMessage\x12!\n\x07message\x18\x02 \x01(\x0b\x32\x10.v1.TypedMessage\x12\x11\n\tsignature\x18\x03 \x01(\t\"\x18\n\x16GetRSAPublicKeyRequest\"&\n\x17GetRSAPublicKeyResponse\x12\x0b\n\x03key\x18\x01 \x01(\t\"\x18\n\x16GetDHParametersRequest\":\n\x17GetDHParametersResponse\x12\t\n\x01p\x18\x01 \x01(\t\x12\t\n\x01g\x18\x02 \x01(\x05\x12\t\n\x01q\x18\x03 \x01(\t\"\x17\n\x15GetDHPublicKeyRequest\"#\n\x16GetDHPublicKeyResponse\x12\t\n\x01y\x18\x01 \x01(\t\":\n\x0fRegisterRequest\x12\n\n\x02id\x18\x01 \x01(\t\x12\x1b\n\x13password_ciphertext\x18\x02 \x01(\t\"\x12\n\x10RegisterResponse\"P\n\x0cLoginRequest\x12\n\n\x02id\x18\x01 \x01(\t\x12\x1b\n\x13password_ciphertext\x18\x02 \x01(\t\x12\x17\n\x0f\x64h_public_key_y\x18\x03 \x01(\t\"\x0f\n\rLoginResponse\"\x1e\n\x0b\x45\x63hoMessage\x12\x0f\n\x07message\x18\x01 \x01(\t\"\x18\n\x16ListOnlineUsersRequest\"+\n\x17ListOnlineUsersResponse\x12\x10\n\x08user_ids\x18\x01 \x03(\t\"*\n\x15\x43hatRequestFromClient\x12\x11\n\trequestee\x18\x01 \x01(\t\"C\n\x15\x43hatRequestFromServer\x12\x11\n\trequester\x18\x02 \x01(\t\x12\x17\n\x0f\x64h_public_key_y\x18\x03 \x01(\t\"1\n\x1d\x43hatRequestFromServerResponse\x12\x10\n\x08\x61\x63\x63\x65pted\x18\x02 \x01(\x08\"g\n\x1d\x43hatRequestFromClientResponse\x12\x10\n\x08\x61\x63\x63\x65pted\x18\x01 \x01(\x08\x12\x0f\n\x05\x65rror\x18\x02 \x01(\tH\x00\x12\x19\n\x0f\x64h_public_key_y\x18\x03 \x01(\tH\x00\x42\x08\n\x06result\"F\n\x13\x43hatMessageToServer\x12\x13\n\x0b\x64\x65stination\x18\x01 \x01(\t\x12\x1a\n\x12message_ciphertext\x18\x03 \x01(\t\"g\n\x13\x43hatMessageResponse\x12\x12\n\nsuccessful\x18\x01 \x01(\x08\x12\r\n\x05\x65rror\x18\x02 \x01(\t\x12-\n\ttimestamp\x18\x03 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\"p\n\x13\x43hatMessageToClient\x12\x0e\n\x06source\x18\x01 \x01(\t\x12-\n\ttimestamp\x18\x02 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x1a\n\x12message_ciphertext\x18\x03 \x01(\t\"6\n\x1bRefreshDHKeyRequestToServer\x12\x17\n\x0f\x64h_public_key_y\x18\x01 \x01(\t\"I\n\x1bRefreshDHKeyRequestToClient\x12\x11\n\trequester\x18\x02 \x01(\t\x12\x17\n\x0f\x64h_public_key_y\x18\x03 \x01(\t\" \n\x12\x43reateGroupRequest\x12\n\n\x02id\x18\x01 \x01(\t\"8\n\x13\x43reateGroupResponse\x12\x12\n\nsuccessful\x18\x01 \x01(\x08\x12\r\n\x05\x65rror\x18\x03 \x01(\t\"\x13\n\x11ListGroupsRequest\"@\n\x05Group\x12\n\n\x02id\x18\x01 \x01(\t\x12\x0f\n\x07members\x18\x02 \x03(\t\x12\x1a\n\x12is_requester_admin\x18\x03 \x01(\x08\"/\n\x12ListGroupsResponse\x12\x19\n\x06groups\x18\x01 \x03(\x0b\x32\t.v1.Group\"&\n\x13GetPublicKeyRequest\x12\x0f\n\x07user_id\x18\x01 \x01(\t\"R\n\x14GetPublicKeyResponse\x12\x12\n\nsuccessful\x18\x01 \x01(\x08\x12\x17\n\x0f\x64h_public_key_y\x18\x02 \x01(\t\x12\r\n\x05\x65rror\x18\x03 \x01(\t\"B\n\x1d\x41\x64\x64GroupMemberRequestToServer\x12\x10\n\x08group_id\x18\x01 \x01(\t\x12\x0f\n\x07user_id\x18\x02 \x01(\t\";\n\x16\x41\x64\x64GroupMemberResponse\x12\x12\n\nsuccessful\x18\x01 \x01(\x08\x12\r\n\x05\x65rror\x18\x02 \x01(\t\"9\n\x1d\x41\x64\x64GroupMemberRequestToClient\x12\x18\n\x05group\x18\x01 \x01(\x0b\x32\t.v1.Group\"B\n\x1d\x41\x64\x64NewGroupMemberNotification\x12\x10\n\x08group_id\x18\x01 \x01(\t\x12\x0f\n\x07user_id\x18\x02 \x01(\t\"W\n\x18GroupChatMessageToServer\x12\x10\n\x08group_id\x18\x01 \x01(\t\x12)\n\x08messages\x18\x03 \x03(\x0b\x32\x17.v1.ChatMessageToServer\"l\n\x18GroupChatMessageResponse\x12\x12\n\nsuccessful\x18\x01 \x01(\x08\x12\r\n\x05\x65rror\x18\x02 \x01(\t\x12-\n\ttimestamp\x18\x03 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\"V\n\x18GroupChatMessageToClient\x12\x10\n\x08group_id\x18\x01 \x01(\t\x12(\n\x07message\x18\x03 \x01(\x0b\x32\x17.v1.ChatMessageToClient\"B\n\x1dRemoveGroupMemberNotification\x12\x10\n\x08group_id\x18\x01 \x01(\t\x12\x0f\n\x07user_id\x18\x02 \x01(\t\"I\n$RemoveMemberFromGroupRequestToServer\x12\x10\n\x08group_id\x18\x01 \x01(\t\x12\x0f\n\x07user_id\x18\x02 \x01(\t\"B\n\x1dRemoveMemberFromGroupResponse\x12\x12\n\nsuccessful\x18\x01 \x01(\x08\x12\r\n\x05\x65rror\x18\x02 \x01(\t\"8\n$RemoveMemberFromGroupRequestToClient\x12\x10\n\x08group_id\x18\x01 \x01(\t\"\x1a\n\x18SessionReadyNotification2\xd0\x02\n\x10MessengerService\x12J\n\x0fGetRSAPublicKey\x12\x1a.v1.GetRSAPublicKeyRequest\x1a\x1b.v1.GetRSAPublicKeyResponse\x12@\n\x0fGetDHParameters\x12\x1a.v1.GetDHParametersRequest\x1a\x11.v1.SignedMessage\x12>\n\x0eGetDHPublicKey\x12\x19.v1.GetDHPublicKeyRequest\x1a\x11.v1.SignedMessage\x12\x35\n\x08Register\x12\x13.v1.RegisterRequest\x1a\x14.v1.RegisterResponse\x12\x37\n\x0cStartSession\x12\x10.v1.TypedMessage\x1a\x11.v1.SignedMessage(\x01\x30\x01\x62\x06proto3')



_TYPEDMESSAGE = DESCRIPTOR.message_types_by_name['TypedMessage']
_SIGNEDMESSAGE = DESCRIPTOR.message_types_by_name['SignedMessage']
_GETRSAPUBLICKEYREQUEST = DESCRIPTOR.message_types_by_name['GetRSAPublicKeyRequest']
_GETRSAPUBLICKEYRESPONSE = DESCRIPTOR.message_types_by_name['GetRSAPublicKeyResponse']
_GETDHPARAMETERSREQUEST = DESCRIPTOR.message_types_by_name['GetDHParametersRequest']
_GETDHPARAMETERSRESPONSE = DESCRIPTOR.message_types_by_name['GetDHParametersResponse']
_GETDHPUBLICKEYREQUEST = DESCRIPTOR.message_types_by_name['GetDHPublicKeyRequest']
_GETDHPUBLICKEYRESPONSE = DESCRIPTOR.message_types_by_name['GetDHPublicKeyResponse']
_REGISTERREQUEST = DESCRIPTOR.message_types_by_name['RegisterRequest']
_REGISTERRESPONSE = DESCRIPTOR.message_types_by_name['RegisterResponse']
_LOGINREQUEST = DESCRIPTOR.message_types_by_name['LoginRequest']
_LOGINRESPONSE = DESCRIPTOR.message_types_by_name['LoginResponse']
_ECHOMESSAGE = DESCRIPTOR.message_types_by_name['EchoMessage']
_LISTONLINEUSERSREQUEST = DESCRIPTOR.message_types_by_name['ListOnlineUsersRequest']
_LISTONLINEUSERSRESPONSE = DESCRIPTOR.message_types_by_name['ListOnlineUsersResponse']
_CHATREQUESTFROMCLIENT = DESCRIPTOR.message_types_by_name['ChatRequestFromClient']
_CHATREQUESTFROMSERVER = DESCRIPTOR.message_types_by_name['ChatRequestFromServer']
_CHATREQUESTFROMSERVERRESPONSE = DESCRIPTOR.message_types_by_name['ChatRequestFromServerResponse']
_CHATREQUESTFROMCLIENTRESPONSE = DESCRIPTOR.message_types_by_name['ChatRequestFromClientResponse']
_CHATMESSAGETOSERVER = DESCRIPTOR.message_types_by_name['ChatMessageToServer']
_CHATMESSAGERESPONSE = DESCRIPTOR.message_types_by_name['ChatMessageResponse']
_CHATMESSAGETOCLIENT = DESCRIPTOR.message_types_by_name['ChatMessageToClient']
_REFRESHDHKEYREQUESTTOSERVER = DESCRIPTOR.message_types_by_name['RefreshDHKeyRequestToServer']
_REFRESHDHKEYREQUESTTOCLIENT = DESCRIPTOR.message_types_by_name['RefreshDHKeyRequestToClient']
_CREATEGROUPREQUEST = DESCRIPTOR.message_types_by_name['CreateGroupRequest']
_CREATEGROUPRESPONSE = DESCRIPTOR.message_types_by_name['CreateGroupResponse']
_LISTGROUPSREQUEST = DESCRIPTOR.message_types_by_name['ListGroupsRequest']
_GROUP = DESCRIPTOR.message_types_by_name['Group']
_LISTGROUPSRESPONSE = DESCRIPTOR.message_types_by_name['ListGroupsResponse']
_GETPUBLICKEYREQUEST = DESCRIPTOR.message_types_by_name['GetPublicKeyRequest']
_GETPUBLICKEYRESPONSE = DESCRIPTOR.message_types_by_name['GetPublicKeyResponse']
_ADDGROUPMEMBERREQUESTTOSERVER = DESCRIPTOR.message_types_by_name['AddGroupMemberRequestToServer']
_ADDGROUPMEMBERRESPONSE = DESCRIPTOR.message_types_by_name['AddGroupMemberResponse']
_ADDGROUPMEMBERREQUESTTOCLIENT = DESCRIPTOR.message_types_by_name['AddGroupMemberRequestToClient']
_ADDNEWGROUPMEMBERNOTIFICATION = DESCRIPTOR.message_types_by_name['AddNewGroupMemberNotification']
_GROUPCHATMESSAGETOSERVER = DESCRIPTOR.message_types_by_name['GroupChatMessageToServer']
_GROUPCHATMESSAGERESPONSE = DESCRIPTOR.message_types_by_name['GroupChatMessageResponse']
_GROUPCHATMESSAGETOCLIENT = DESCRIPTOR.message_types_by_name['GroupChatMessageToClient']
_REMOVEGROUPMEMBERNOTIFICATION = DESCRIPTOR.message_types_by_name['RemoveGroupMemberNotification']
_REMOVEMEMBERFROMGROUPREQUESTTOSERVER = DESCRIPTOR.message_types_by_name['RemoveMemberFromGroupRequestToServer']
_REMOVEMEMBERFROMGROUPRESPONSE = DESCRIPTOR.message_types_by_name['RemoveMemberFromGroupResponse']
_REMOVEMEMBERFROMGROUPREQUESTTOCLIENT = DESCRIPTOR.message_types_by_name['RemoveMemberFromGroupRequestToClient']
_SESSIONREADYNOTIFICATION = DESCRIPTOR.message_types_by_name['SessionReadyNotification']
TypedMessage = _reflection.GeneratedProtocolMessageType('TypedMessage', (_message.Message,), {
  'DESCRIPTOR' : _TYPEDMESSAGE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.TypedMessage)
  })
_sym_db.RegisterMessage(TypedMessage)

SignedMessage = _reflection.GeneratedProtocolMessageType('SignedMessage', (_message.Message,), {
  'DESCRIPTOR' : _SIGNEDMESSAGE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.SignedMessage)
  })
_sym_db.RegisterMessage(SignedMessage)

GetRSAPublicKeyRequest = _reflection.GeneratedProtocolMessageType('GetRSAPublicKeyRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETRSAPUBLICKEYREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetRSAPublicKeyRequest)
  })
_sym_db.RegisterMessage(GetRSAPublicKeyRequest)

GetRSAPublicKeyResponse = _reflection.GeneratedProtocolMessageType('GetRSAPublicKeyResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETRSAPUBLICKEYRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetRSAPublicKeyResponse)
  })
_sym_db.RegisterMessage(GetRSAPublicKeyResponse)

GetDHParametersRequest = _reflection.GeneratedProtocolMessageType('GetDHParametersRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETDHPARAMETERSREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetDHParametersRequest)
  })
_sym_db.RegisterMessage(GetDHParametersRequest)

GetDHParametersResponse = _reflection.GeneratedProtocolMessageType('GetDHParametersResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETDHPARAMETERSRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetDHParametersResponse)
  })
_sym_db.RegisterMessage(GetDHParametersResponse)

GetDHPublicKeyRequest = _reflection.GeneratedProtocolMessageType('GetDHPublicKeyRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETDHPUBLICKEYREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetDHPublicKeyRequest)
  })
_sym_db.RegisterMessage(GetDHPublicKeyRequest)

GetDHPublicKeyResponse = _reflection.GeneratedProtocolMessageType('GetDHPublicKeyResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETDHPUBLICKEYRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetDHPublicKeyResponse)
  })
_sym_db.RegisterMessage(GetDHPublicKeyResponse)

RegisterRequest = _reflection.GeneratedProtocolMessageType('RegisterRequest', (_message.Message,), {
  'DESCRIPTOR' : _REGISTERREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RegisterRequest)
  })
_sym_db.RegisterMessage(RegisterRequest)

RegisterResponse = _reflection.GeneratedProtocolMessageType('RegisterResponse', (_message.Message,), {
  'DESCRIPTOR' : _REGISTERRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RegisterResponse)
  })
_sym_db.RegisterMessage(RegisterResponse)

LoginRequest = _reflection.GeneratedProtocolMessageType('LoginRequest', (_message.Message,), {
  'DESCRIPTOR' : _LOGINREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.LoginRequest)
  })
_sym_db.RegisterMessage(LoginRequest)

LoginResponse = _reflection.GeneratedProtocolMessageType('LoginResponse', (_message.Message,), {
  'DESCRIPTOR' : _LOGINRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.LoginResponse)
  })
_sym_db.RegisterMessage(LoginResponse)

EchoMessage = _reflection.GeneratedProtocolMessageType('EchoMessage', (_message.Message,), {
  'DESCRIPTOR' : _ECHOMESSAGE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.EchoMessage)
  })
_sym_db.RegisterMessage(EchoMessage)

ListOnlineUsersRequest = _reflection.GeneratedProtocolMessageType('ListOnlineUsersRequest', (_message.Message,), {
  'DESCRIPTOR' : _LISTONLINEUSERSREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ListOnlineUsersRequest)
  })
_sym_db.RegisterMessage(ListOnlineUsersRequest)

ListOnlineUsersResponse = _reflection.GeneratedProtocolMessageType('ListOnlineUsersResponse', (_message.Message,), {
  'DESCRIPTOR' : _LISTONLINEUSERSRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ListOnlineUsersResponse)
  })
_sym_db.RegisterMessage(ListOnlineUsersResponse)

ChatRequestFromClient = _reflection.GeneratedProtocolMessageType('ChatRequestFromClient', (_message.Message,), {
  'DESCRIPTOR' : _CHATREQUESTFROMCLIENT,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ChatRequestFromClient)
  })
_sym_db.RegisterMessage(ChatRequestFromClient)

ChatRequestFromServer = _reflection.GeneratedProtocolMessageType('ChatRequestFromServer', (_message.Message,), {
  'DESCRIPTOR' : _CHATREQUESTFROMSERVER,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ChatRequestFromServer)
  })
_sym_db.RegisterMessage(ChatRequestFromServer)

ChatRequestFromServerResponse = _reflection.GeneratedProtocolMessageType('ChatRequestFromServerResponse', (_message.Message,), {
  'DESCRIPTOR' : _CHATREQUESTFROMSERVERRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ChatRequestFromServerResponse)
  })
_sym_db.RegisterMessage(ChatRequestFromServerResponse)

ChatRequestFromClientResponse = _reflection.GeneratedProtocolMessageType('ChatRequestFromClientResponse', (_message.Message,), {
  'DESCRIPTOR' : _CHATREQUESTFROMCLIENTRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ChatRequestFromClientResponse)
  })
_sym_db.RegisterMessage(ChatRequestFromClientResponse)

ChatMessageToServer = _reflection.GeneratedProtocolMessageType('ChatMessageToServer', (_message.Message,), {
  'DESCRIPTOR' : _CHATMESSAGETOSERVER,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ChatMessageToServer)
  })
_sym_db.RegisterMessage(ChatMessageToServer)

ChatMessageResponse = _reflection.GeneratedProtocolMessageType('ChatMessageResponse', (_message.Message,), {
  'DESCRIPTOR' : _CHATMESSAGERESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ChatMessageResponse)
  })
_sym_db.RegisterMessage(ChatMessageResponse)

ChatMessageToClient = _reflection.GeneratedProtocolMessageType('ChatMessageToClient', (_message.Message,), {
  'DESCRIPTOR' : _CHATMESSAGETOCLIENT,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ChatMessageToClient)
  })
_sym_db.RegisterMessage(ChatMessageToClient)

RefreshDHKeyRequestToServer = _reflection.GeneratedProtocolMessageType('RefreshDHKeyRequestToServer', (_message.Message,), {
  'DESCRIPTOR' : _REFRESHDHKEYREQUESTTOSERVER,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RefreshDHKeyRequestToServer)
  })
_sym_db.RegisterMessage(RefreshDHKeyRequestToServer)

RefreshDHKeyRequestToClient = _reflection.GeneratedProtocolMessageType('RefreshDHKeyRequestToClient', (_message.Message,), {
  'DESCRIPTOR' : _REFRESHDHKEYREQUESTTOCLIENT,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RefreshDHKeyRequestToClient)
  })
_sym_db.RegisterMessage(RefreshDHKeyRequestToClient)

CreateGroupRequest = _reflection.GeneratedProtocolMessageType('CreateGroupRequest', (_message.Message,), {
  'DESCRIPTOR' : _CREATEGROUPREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.CreateGroupRequest)
  })
_sym_db.RegisterMessage(CreateGroupRequest)

CreateGroupResponse = _reflection.GeneratedProtocolMessageType('CreateGroupResponse', (_message.Message,), {
  'DESCRIPTOR' : _CREATEGROUPRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.CreateGroupResponse)
  })
_sym_db.RegisterMessage(CreateGroupResponse)

ListGroupsRequest = _reflection.GeneratedProtocolMessageType('ListGroupsRequest', (_message.Message,), {
  'DESCRIPTOR' : _LISTGROUPSREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ListGroupsRequest)
  })
_sym_db.RegisterMessage(ListGroupsRequest)

Group = _reflection.GeneratedProtocolMessageType('Group', (_message.Message,), {
  'DESCRIPTOR' : _GROUP,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.Group)
  })
_sym_db.RegisterMessage(Group)

ListGroupsResponse = _reflection.GeneratedProtocolMessageType('ListGroupsResponse', (_message.Message,), {
  'DESCRIPTOR' : _LISTGROUPSRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.ListGroupsResponse)
  })
_sym_db.RegisterMessage(ListGroupsResponse)

GetPublicKeyRequest = _reflection.GeneratedProtocolMessageType('GetPublicKeyRequest', (_message.Message,), {
  'DESCRIPTOR' : _GETPUBLICKEYREQUEST,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetPublicKeyRequest)
  })
_sym_db.RegisterMessage(GetPublicKeyRequest)

GetPublicKeyResponse = _reflection.GeneratedProtocolMessageType('GetPublicKeyResponse', (_message.Message,), {
  'DESCRIPTOR' : _GETPUBLICKEYRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GetPublicKeyResponse)
  })
_sym_db.RegisterMessage(GetPublicKeyResponse)

AddGroupMemberRequestToServer = _reflection.GeneratedProtocolMessageType('AddGroupMemberRequestToServer', (_message.Message,), {
  'DESCRIPTOR' : _ADDGROUPMEMBERREQUESTTOSERVER,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.AddGroupMemberRequestToServer)
  })
_sym_db.RegisterMessage(AddGroupMemberRequestToServer)

AddGroupMemberResponse = _reflection.GeneratedProtocolMessageType('AddGroupMemberResponse', (_message.Message,), {
  'DESCRIPTOR' : _ADDGROUPMEMBERRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.AddGroupMemberResponse)
  })
_sym_db.RegisterMessage(AddGroupMemberResponse)

AddGroupMemberRequestToClient = _reflection.GeneratedProtocolMessageType('AddGroupMemberRequestToClient', (_message.Message,), {
  'DESCRIPTOR' : _ADDGROUPMEMBERREQUESTTOCLIENT,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.AddGroupMemberRequestToClient)
  })
_sym_db.RegisterMessage(AddGroupMemberRequestToClient)

AddNewGroupMemberNotification = _reflection.GeneratedProtocolMessageType('AddNewGroupMemberNotification', (_message.Message,), {
  'DESCRIPTOR' : _ADDNEWGROUPMEMBERNOTIFICATION,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.AddNewGroupMemberNotification)
  })
_sym_db.RegisterMessage(AddNewGroupMemberNotification)

GroupChatMessageToServer = _reflection.GeneratedProtocolMessageType('GroupChatMessageToServer', (_message.Message,), {
  'DESCRIPTOR' : _GROUPCHATMESSAGETOSERVER,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GroupChatMessageToServer)
  })
_sym_db.RegisterMessage(GroupChatMessageToServer)

GroupChatMessageResponse = _reflection.GeneratedProtocolMessageType('GroupChatMessageResponse', (_message.Message,), {
  'DESCRIPTOR' : _GROUPCHATMESSAGERESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GroupChatMessageResponse)
  })
_sym_db.RegisterMessage(GroupChatMessageResponse)

GroupChatMessageToClient = _reflection.GeneratedProtocolMessageType('GroupChatMessageToClient', (_message.Message,), {
  'DESCRIPTOR' : _GROUPCHATMESSAGETOCLIENT,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.GroupChatMessageToClient)
  })
_sym_db.RegisterMessage(GroupChatMessageToClient)

RemoveGroupMemberNotification = _reflection.GeneratedProtocolMessageType('RemoveGroupMemberNotification', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEGROUPMEMBERNOTIFICATION,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RemoveGroupMemberNotification)
  })
_sym_db.RegisterMessage(RemoveGroupMemberNotification)

RemoveMemberFromGroupRequestToServer = _reflection.GeneratedProtocolMessageType('RemoveMemberFromGroupRequestToServer', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEMEMBERFROMGROUPREQUESTTOSERVER,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RemoveMemberFromGroupRequestToServer)
  })
_sym_db.RegisterMessage(RemoveMemberFromGroupRequestToServer)

RemoveMemberFromGroupResponse = _reflection.GeneratedProtocolMessageType('RemoveMemberFromGroupResponse', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEMEMBERFROMGROUPRESPONSE,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RemoveMemberFromGroupResponse)
  })
_sym_db.RegisterMessage(RemoveMemberFromGroupResponse)

RemoveMemberFromGroupRequestToClient = _reflection.GeneratedProtocolMessageType('RemoveMemberFromGroupRequestToClient', (_message.Message,), {
  'DESCRIPTOR' : _REMOVEMEMBERFROMGROUPREQUESTTOCLIENT,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.RemoveMemberFromGroupRequestToClient)
  })
_sym_db.RegisterMessage(RemoveMemberFromGroupRequestToClient)

SessionReadyNotification = _reflection.GeneratedProtocolMessageType('SessionReadyNotification', (_message.Message,), {
  'DESCRIPTOR' : _SESSIONREADYNOTIFICATION,
  '__module__' : 'messenger.api.v1.messenger_pb2'
  # @@protoc_insertion_point(class_scope:v1.SessionReadyNotification)
  })
_sym_db.RegisterMessage(SessionReadyNotification)

_MESSENGERSERVICE = DESCRIPTOR.services_by_name['MessengerService']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _TYPEDMESSAGE._serialized_start=73
  _TYPEDMESSAGE._serialized_end=149
  _SIGNEDMESSAGE._serialized_start=151
  _SIGNEDMESSAGE._serialized_end=220
  _GETRSAPUBLICKEYREQUEST._serialized_start=222
  _GETRSAPUBLICKEYREQUEST._serialized_end=246
  _GETRSAPUBLICKEYRESPONSE._serialized_start=248
  _GETRSAPUBLICKEYRESPONSE._serialized_end=286
  _GETDHPARAMETERSREQUEST._serialized_start=288
  _GETDHPARAMETERSREQUEST._serialized_end=312
  _GETDHPARAMETERSRESPONSE._serialized_start=314
  _GETDHPARAMETERSRESPONSE._serialized_end=372
  _GETDHPUBLICKEYREQUEST._serialized_start=374
  _GETDHPUBLICKEYREQUEST._serialized_end=397
  _GETDHPUBLICKEYRESPONSE._serialized_start=399
  _GETDHPUBLICKEYRESPONSE._serialized_end=434
  _REGISTERREQUEST._serialized_start=436
  _REGISTERREQUEST._serialized_end=494
  _REGISTERRESPONSE._serialized_start=496
  _REGISTERRESPONSE._serialized_end=514
  _LOGINREQUEST._serialized_start=516
  _LOGINREQUEST._serialized_end=596
  _LOGINRESPONSE._serialized_start=598
  _LOGINRESPONSE._serialized_end=613
  _ECHOMESSAGE._serialized_start=615
  _ECHOMESSAGE._serialized_end=645
  _LISTONLINEUSERSREQUEST._serialized_start=647
  _LISTONLINEUSERSREQUEST._serialized_end=671
  _LISTONLINEUSERSRESPONSE._serialized_start=673
  _LISTONLINEUSERSRESPONSE._serialized_end=716
  _CHATREQUESTFROMCLIENT._serialized_start=718
  _CHATREQUESTFROMCLIENT._serialized_end=760
  _CHATREQUESTFROMSERVER._serialized_start=762
  _CHATREQUESTFROMSERVER._serialized_end=829
  _CHATREQUESTFROMSERVERRESPONSE._serialized_start=831
  _CHATREQUESTFROMSERVERRESPONSE._serialized_end=880
  _CHATREQUESTFROMCLIENTRESPONSE._serialized_start=882
  _CHATREQUESTFROMCLIENTRESPONSE._serialized_end=985
  _CHATMESSAGETOSERVER._serialized_start=987
  _CHATMESSAGETOSERVER._serialized_end=1057
  _CHATMESSAGERESPONSE._serialized_start=1059
  _CHATMESSAGERESPONSE._serialized_end=1162
  _CHATMESSAGETOCLIENT._serialized_start=1164
  _CHATMESSAGETOCLIENT._serialized_end=1276
  _REFRESHDHKEYREQUESTTOSERVER._serialized_start=1278
  _REFRESHDHKEYREQUESTTOSERVER._serialized_end=1332
  _REFRESHDHKEYREQUESTTOCLIENT._serialized_start=1334
  _REFRESHDHKEYREQUESTTOCLIENT._serialized_end=1407
  _CREATEGROUPREQUEST._serialized_start=1409
  _CREATEGROUPREQUEST._serialized_end=1441
  _CREATEGROUPRESPONSE._serialized_start=1443
  _CREATEGROUPRESPONSE._serialized_end=1499
  _LISTGROUPSREQUEST._serialized_start=1501
  _LISTGROUPSREQUEST._serialized_end=1520
  _GROUP._serialized_start=1522
  _GROUP._serialized_end=1586
  _LISTGROUPSRESPONSE._serialized_start=1588
  _LISTGROUPSRESPONSE._serialized_end=1635
  _GETPUBLICKEYREQUEST._serialized_start=1637
  _GETPUBLICKEYREQUEST._serialized_end=1675
  _GETPUBLICKEYRESPONSE._serialized_start=1677
  _GETPUBLICKEYRESPONSE._serialized_end=1759
  _ADDGROUPMEMBERREQUESTTOSERVER._serialized_start=1761
  _ADDGROUPMEMBERREQUESTTOSERVER._serialized_end=1827
  _ADDGROUPMEMBERRESPONSE._serialized_start=1829
  _ADDGROUPMEMBERRESPONSE._serialized_end=1888
  _ADDGROUPMEMBERREQUESTTOCLIENT._serialized_start=1890
  _ADDGROUPMEMBERREQUESTTOCLIENT._serialized_end=1947
  _ADDNEWGROUPMEMBERNOTIFICATION._serialized_start=1949
  _ADDNEWGROUPMEMBERNOTIFICATION._serialized_end=2015
  _GROUPCHATMESSAGETOSERVER._serialized_start=2017
  _GROUPCHATMESSAGETOSERVER._serialized_end=2104
  _GROUPCHATMESSAGERESPONSE._serialized_start=2106
  _GROUPCHATMESSAGERESPONSE._serialized_end=2214
  _GROUPCHATMESSAGETOCLIENT._serialized_start=2216
  _GROUPCHATMESSAGETOCLIENT._serialized_end=2302
  _REMOVEGROUPMEMBERNOTIFICATION._serialized_start=2304
  _REMOVEGROUPMEMBERNOTIFICATION._serialized_end=2370
  _REMOVEMEMBERFROMGROUPREQUESTTOSERVER._serialized_start=2372
  _REMOVEMEMBERFROMGROUPREQUESTTOSERVER._serialized_end=2445
  _REMOVEMEMBERFROMGROUPRESPONSE._serialized_start=2447
  _REMOVEMEMBERFROMGROUPRESPONSE._serialized_end=2513
  _REMOVEMEMBERFROMGROUPREQUESTTOCLIENT._serialized_start=2515
  _REMOVEMEMBERFROMGROUPREQUESTTOCLIENT._serialized_end=2571
  _SESSIONREADYNOTIFICATION._serialized_start=2573
  _SESSIONREADYNOTIFICATION._serialized_end=2599
  _MESSENGERSERVICE._serialized_start=2602
  _MESSENGERSERVICE._serialized_end=2938
# @@protoc_insertion_point(module_scope)
