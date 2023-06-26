import uuid
from typing import Optional

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
    id = models.CharField(max_length=256, unique=True, primary_key=True, default=uuid.uuid4)
    user = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    dh_public_key = models.BinaryField()
    dh_shared_secret = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def public_key_signature(self) -> str:
        return sha256_hash(self.dh_public_key).hex()

    @property
    def shared_secret_signature(self) -> str:
        return sha256_hash(self.dh_shared_secret).hex()
