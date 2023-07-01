import uuid
from typing import Optional, Type

import google.protobuf.message
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from messenger.api.v1 import messenger_pb2 as m


def num2bytes(num: int) -> bytes:
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')


def sha256_hash(message: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    return digest.finalize()


def encrypt_aes(plaintext: bytes, key: bytes) -> bytes:
    plaintext = plaintext + b"\x00" * (16 - len(plaintext) % 16)
    iv = key[:16]
    # Create a cipher using AES algorithm in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Encrypt the message
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def decrypt_aes(ciphertext: bytes, key: bytes) -> bytes:
    iv = key[:16]
    # Create a cipher using AES algorithm in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypter = cipher.decryptor()
    # Decrypt the message
    plaintext = decrypter.update(ciphertext) + decrypter.finalize()
    # Remove the padding
    plaintext = plaintext.rstrip(b"\x00")
    return plaintext


def encrypt_rsa(plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_rsa(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign(data: bytes, private_key: rsa.RSAPrivateKey) -> str:
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    ).hex()


def verify_signature(data: bytes, signature: str, public_key: rsa.RSAPublicKey) -> None:
    public_key.verify(
        bytes.fromhex(signature),
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def sign_message(message: google.protobuf.message.Message, private_key: rsa.RSAPrivateKey,
                 request_id: Optional[str] = None,
                 aes_key: Optional[bytes] = None) -> m.SignedMessage:
    message_bytes = message.SerializeToString()
    type_ = message.DESCRIPTOR.name
    request_id = request_id or str(uuid.uuid4())
    signature = sign(message_bytes + request_id.encode() + type_.encode(), private_key)
    if aes_key:
        message_bytes = encrypt_aes(message_bytes, aes_key)
    typed_message = m.TypedMessage(
        request_id=request_id,
        type=type_,
        value=message_bytes,
    )
    return m.SignedMessage(message=typed_message, signature=signature)


def parse_typed_message(typed_message: m.TypedMessage) -> google.protobuf.message.Message:
    message = getattr(m, typed_message.type)()
    if typed_message.value:
        message.ParseFromString(typed_message.value)
    return message


def parse_signed_message(signed_message: m.SignedMessage, public_key: rsa.RSAPublicKey,
                         aes_key: Optional[bytes] = None) -> google.protobuf.message.Message:
    message_bytes = signed_message.message.value
    if aes_key:
        message_bytes = decrypt_aes(message_bytes, aes_key)
    signed_message.message.value = message_bytes
    verify_signature(message_bytes + signed_message.message.request_id.encode() + signed_message.message.type.encode(),
                     signed_message.signature,
                     public_key)
    return parse_typed_message(signed_message.message)


def isoftype(message: m.TypedMessage, type: Type[google.protobuf.message.Message]) -> bool:
    return message.type == type.DESCRIPTOR.name
