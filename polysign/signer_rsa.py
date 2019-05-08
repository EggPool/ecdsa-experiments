
import json

from hashlib import sha224
from base64 import b64encode, b64decode
from polysign.signer import Signer, SignerType
from typing import Union

from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Protocol.KDF import PBKDF2


class SignerRSA(Signer):

    __slots__ = ('_key', )

    def __init__(self, private_key: Union[bytes, str]=b'', public_key: Union[bytes, str]=b'', address: str=''):
        super().__init__(private_key, public_key, address)
        self._type = SignerType.RSA
        # For the Key object
        self._key = None

    def to_json(self):
        """for RSA, keys are stored as PEM format, not binary"""
        info = self.to_dict()
        return json.dumps(info)

    def from_private_key(self, private_key: Union[bytes, str]):
        if type(private_key) is not str:
            raise RuntimeError('RSA private key have to be strings')
        try:
            key = RSA.importKey(private_key)
            public_key_readable = key.publickey().exportKey().decode("utf-8")
            if len(public_key_readable) not in (271, 799):
                raise ValueError("Invalid public key length: {}".format(len(public_key_readable)))
            address = sha224(public_key_readable.encode('utf-8')).hexdigest()
            # If we had no error, we can store
            self._key = key
            self._private_key = private_key
            self._public_key = public_key_readable
            self._address = address

        except Exception as e:
            print("Exception {} reading RSA private key".format(e))

    def from_full_info(self, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       verify: bool=True):
        print('TODO')

    def from_seed(self, seed: str=''):
        print('TODO')

