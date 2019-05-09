"""
Abstract and Factory class to handle various Bismuth signature and addresses schemes
"""

import json

from abc import ABC, abstractmethod
from enum import Enum
from typing import Union


__version__ = '0.0.1'


class SignerType(Enum):
    """
    Possible signing schemes
    """
    NONE = 0
    RSA = 1
    ECDSA = 2
    EDD25519 = 3


class Signer(ABC):

    # Slots allow to spare ram when there can be several instances
    __slot__ = ('_private_key', '_public_key', '_address', '_type', '_compressed', 'verbose')

    def __init__(self, private_key: Union[bytes, str]=b'', public_key: Union[bytes, str]=b'', address: str='',
                 compressed: bool=True):
        self._private_key = private_key
        self._public_key = public_key
        self._address = address
        self._type = SignerType.NONE
        self.verbose = False
        self._compressed = compressed

    @property
    def compressed(self):
        return self._compressed

    @property
    def type(self):
        """Name of the signer instance"""
        return self._type.name

    @abstractmethod
    def from_private_key(self, private_key: Union[bytes, str]):
        pass

    @abstractmethod
    def from_full_info(self, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       verify: bool=True):
        pass

    @abstractmethod
    def from_seed(self, seed: str=''):
        """Use seed == '' to generate a random key"""
        pass

    @classmethod
    @abstractmethod
    def public_key_to_address(cls, public_key: Union[bytes, str]) -> str:
        """Reconstruct an address from the public key"""
        pass

    @classmethod
    @abstractmethod
    def verify_signature(cls, signature: Union[bytes, str], public_key: Union[bytes, str], buffer: bytes,
                         address: str=''):
        """Verify signature from raw signature & pubkey. Address may be used to determine the sig type"""
        pass

    @classmethod
    @abstractmethod
    def verify_bis_signature(cls, signature: str, public_key: str, buffer: bytes, address: str=''):
        """Verify signature from bismuth tx network format
        pubkey is b64 encoded twice - ecdsa and ed25519 are b64 encoded)"""
        pass

    def to_dict(self):
        """Returns core properties as dict, compact bin form"""
        info = {'address': self._address, 'private_key': self._private_key, 'public_key': self._public_key,
                'compressed': self._compressed, 'type': self._type.name}
        return info

    def to_json(self):
        """Returns a json string, with bin items as hex strings"""
        info = self.to_dict()
        info['private_key'] = info['private_key'].hex()
        info['public_key'] = info['public_key'].hex()
        return json.dumps(info)





