import uuid
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from django.contrib.auth.models import User
from django.db import models

from messenger.utils import sha256_hash


class Configuration(models.Model):
    name = models.CharField(max_length=256, unique=True)
    value = models.CharField(max_length=1024)

    @classmethod
    def get(cls, name: str, default=None) -> Optional[str]:
        try:
            return cls.objects.get(name=name).value
        except cls.DoesNotExist:
            return default

    @classmethod
    def set(cls, name: str, value: str):
        try:
            config = cls.objects.get(name=name)
            config.value = value
            config.save()
        except cls.DoesNotExist:
            cls.objects.create(name=name, value=value)

    @classmethod
    def exists(cls, name: str) -> bool:
        return cls.objects.filter(name=name).exists()

    def __str__(self):
        return self.name + ': ' + self.value

    class Meta:
        indexes = [
            models.Index(fields=['name']),
        ]


class ServerKey(models.Model):
    name = models.CharField(max_length=256, unique=True)
    value = models.BinaryField()

    @property
    def signature(self) -> str:
        return sha256_hash(self.value).hex()

    @classmethod
    def get(cls, name: str, default=None) -> Optional[bytes]:
        try:
            return cls.objects.get(name=name).value
        except cls.DoesNotExist:
            return default

    @classmethod
    def set(cls, name: str, value: bytes):
        try:
            key: cls = cls.objects.get(name=name)
            key.value = value
            key.save()
        except cls.DoesNotExist:
            cls.objects.create(name=name, value=value)

    @classmethod
    def exists(cls, name: str) -> bool:
        return cls.objects.filter(name=name).exists()


class Session(models.Model):
    id = models.UUIDField(unique=True, primary_key=True, default=uuid.uuid4)
    user = models.OneToOneField('auth.User', on_delete=models.CASCADE, related_name='session')
    dh_public_key = models.BinaryField()
    dh_shared_secret = models.BinaryField()
    rsa_public_key = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def dh_public_key_signature(self) -> str:
        return sha256_hash(self.dh_public_key).hex()

    @property
    def rsa_public_key_signature(self) -> str:
        return sha256_hash(self.rsa_public_key).hex()

    @property
    def shared_secret_signature(self) -> str:
        return sha256_hash(self.dh_shared_secret).hex()

    @property
    def parsed_dh_public_key(self) -> dh.DHPublicKey:
        return load_pem_public_key(self.dh_public_key, default_backend())

    @parsed_dh_public_key.setter
    def parsed_dh_public_key(self, value: dh.DHPublicKey):
        self.dh_public_key = value.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class ChatRequest(models.Model):
    id = models.UUIDField(unique=True, primary_key=True, default=uuid.uuid4)
    requester = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name='chat_requests_sent')
    requestee = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name='chat_requests_received')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Status(models.TextChoices):
        PENDING = 'PENDING'
        ACCEPTED = 'ACCEPTED'
        REJECTED = 'REJECTED'

    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)

    class Meta:
        indexes = [
            models.Index(fields=['requester', 'requestee']),
        ]


class GroupChat(models.Model):
    id = models.CharField(max_length=256, unique=True, primary_key=True)
    members = models.ManyToManyField('auth.User', related_name='group_chats', through='GroupChatMember')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def admin(self) -> User:
        return self.members.get(groupchatmember__is_admin=True)


class GroupChatMember(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    group_chat = models.ForeignKey('GroupChat', on_delete=models.CASCADE)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'group_chat')
        indexes = [
            models.Index(fields=['user', 'group_chat']),
        ]


class Request(models.Model):
    id = models.UUIDField(unique=True, primary_key=True)
    requester = models.ForeignKey('auth.User', on_delete=models.CASCADE, related_name='requests_sent')
    request_type = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.requester.username}.{self.request_type}(id={self.id}, at={self.created_at})'
