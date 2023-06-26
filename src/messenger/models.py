from typing import Optional

from django.db import models


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
