"""

"""

import base58
import hashlib
import random
from os import urandom
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
ADDRESS_VERSION = b'\x01\x75\x07'  # CRW


class SignerECDSA(Signer):

    __slots__ = ('_key', )

    def __init__(self, private_key: Union[bytes, str]=b'', public_key: Union[bytes, str]=b'', address: str=''):
        super().__init__(private_key, public_key, address)
        self._key = None
        self._type = SignerType.ECDSA

    def from_private_key(self, private_key: Union[bytes, str]):
        """Accepts both bytes[32] or str (hex format)"""
        if type(private_key) == str:
            return self.from_seed(private_key)
        return self.from_seed(private_key.hex())

    def from_full_info(self, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       verify: bool=True):
        print('TODO - ecdsa.from_full_info')

    def from_seed(self, seed: str=''):
        """Creates key from seed - for ecdsa, seed = pk - 32 bytes random buffer"""
        if len(seed) > 64:
            # Too long seed, trim (could use better scheme for more entropy)
            seed = seed[:64]
        elif seed == '':
            # No seed, use urandom
            seed = urandom(32)
        elif len(seed) < 64:
            # Too short seed, use as PRNG seed
            random.seed(seed)
            seed = random.getrandbits(32*8).hex()
        try:
            key = PrivateKey.from_hex(seed)
            public_key = key.public_key.format(compressed=True).hex()
            print("Public Key", public_key)
            self._key = key
            self._private_key = key.to_hex()  # == seed
            self._public_key = public_key
        except Exception as e:
            print("Exception {} reading RSA private key".format(e))
        # print("identifier", self.identifier().hex())
        self._address = self.address()

    def identifier(self):
        """Returns double hash of pubkey as per btc standards"""
        return hashlib.new('ripemd160', sha256(bytes.fromhex(self._public_key)).digest()).digest()

    def address(self):
        """Returns properly serialized address from pubkey as per btc standards"""
        vh160 = ADDRESS_VERSION + self.identifier()  # raw content
        chk = sha256(sha256(vh160).digest()).digest()[:4]
        return base58.b58encode(vh160 + chk).decode('utf-8')
