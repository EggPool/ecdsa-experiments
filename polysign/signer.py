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
    BTC = 1000  # For test vectors


class Signer(ABC):

    # Slots allow to spare ram when there can be several instances
    __slot__ = ('_private_key', '_public_key', '_address', '_type', 'verbose')

    def __init__(self, private_key: Union[bytes, str]=b'', public_key: Union[bytes, str]=b'', address: str=''):
        self._private_key = private_key
        self._public_key = public_key
        self._address = address
        self._type = SignerType.NONE
        self.verbose = False

    @abstractmethod
    def from_private_key(self, private_key: Union[bytes, str]):
        pass

    @abstractmethod
    def from_full_info(self, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       verify: bool=True):
        pass

    @abstractmethod
    def from_seed(self, seed: str=''):
        pass

    def to_dict(self):
        """Returns core properties as dict, compact bin form"""
        info = {'address': self._address, 'private_key': self._private_key, 'public_key': self._public_key,
                'type': self._type.name}
        return info

    def to_json(self):
        """Returns a json string, with bin items as hex strings"""
        info = self.to_dict()
        info['private_key'] = info['private_key'].hex()
        info['public_key'] = info['public_key'].hex()
        return json.dumps(info)





