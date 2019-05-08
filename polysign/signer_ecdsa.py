"""

"""

import base58
import hashlib
from polysign.signer import Signer, SignerType
from typing import Union
from hashlib import sha256

from coincurve import PrivateKey, PublicKey
# from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError
# FR: move from python ecdsa to libsecp256k1, supposed to be way faster to sign and verify transactions.
# Use test cases and test vectors to make sure all is the same.
# 2 candidates, https://github.com/ofek/coincurve  seems up to date and pretty good
# https://github.com/ludbb/secp256k1-py   is older


ADDRESS_VERSION = b'\x6f'  # Bitcoin testnet
ADDRESS_VERSION = b'\x00'  # Bitcoin mainnet


class SignerECDSA(Signer):

    __slots__ = ('_key', )

    def __init__(self, private_key: Union[bytes, str]=b'', public_key: Union[bytes, str]=b'', address: str=''):
        super().__init__(private_key, public_key, address)
        self._key = None
        self._type = SignerType.ECDSA

    def from_private_key(self, private_key: Union[bytes, str]):
        print('TODO')

    def from_full_info(self, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       verify: bool=True):
        print('TODO')

    def from_seed(self, seed: str=''):
        print('TODO ecdsa from seed {}'.format(seed))
        try:
            key = PrivateKey.from_hex(seed)
            public_key = key.public_key.format(compressed=True).hex()
            print("Public Key", public_key)
            self._key = key
            self._private_key = key.to_hex()  # == seed
            self._public_key = public_key
        except Exception as e:
            print("Exception {} reading RSA private key".format(e))
        print("identifier", self.identifier().hex())
        self._address = self.address()

    def identifier(self):
        """Returns double hash of pubkey"""
        # faafd1966c79c472360ef1cf8860169df6e7554a
        return hashlib.new('ripemd160', sha256(bytes.fromhex(self._public_key)).digest()).digest()

    def address(self):
        # 1PrWZ4CXSXWbg87XS9ShhwMV6TiSXtycT7
        vh160 = ADDRESS_VERSION + self.identifier()  # raw content
        chk = sha256(sha256(vh160).digest()).digest()[:4]
        return base58.b58encode(vh160 + chk).decode('utf-8')
