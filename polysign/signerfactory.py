from os import urandom
from polysign.signer import Signer, SignerType
from polysign.signer_rsa import SignerRSA
from polysign.signer_ecdsa import SignerECDSA
from typing import Union


class SignerFactory():
    """"""

    @classmethod
    def from_private_key(cls, private_key: Union[bytes, str], signer_type: SignerType=SignerType.RSA) -> Signer:
        """Detect the type of the key, creates and return the matching signer"""
        # TODO
        signer = SignerRSA()
        signer.from_private_key(private_key)
        return signer

    @classmethod
    def from_full_info(cls, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       signer_type: SignerType=SignerType.RSA, verify: bool=True) -> Signer:
        pass

    @classmethod
    def from_seed(cls, seed: str='', signer_type: SignerType=SignerType.RSA) -> Signer:
        if seed == '':
            seed = urandom(32).hex()
        if signer_type == SignerType.RSA:
            signer = SignerRSA()
            signer.from_seed(seed)
            return signer
        if signer_type == SignerType.ECDSA:
            signer = SignerECDSA()
            signer.from_seed(seed)
            return signer
        raise ValueError("Unsupported Key type")
