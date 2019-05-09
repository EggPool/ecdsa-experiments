import re
from os import urandom
from typing import Union

from polysign.signer import Signer, SignerType, SignerSubType
from polysign.signer_btc import SignerBTC
from polysign.signer_crw import SignerCRW
from polysign.signer_ecdsa import SignerECDSA
from polysign.signer_rsa import SignerRSA

RE_RSA_ADDRESS = re.compile(r"[abcdef0123456789]{56}")
# TODO: improve that ECDSA one
RE_ECDSA_ADDRESS = re.compile(r"^Bis")


class SignerFactory():
    """"""

    @classmethod
    def from_private_key(cls, private_key: Union[bytes, str], signer_type: SignerType=SignerType.RSA,
                         subtype: SignerSubType=SignerSubType.MAINNET_REGULAR) -> Signer:
        """Detect the type of the key, creates and return the matching signer"""
        # TODO: detect by private_key
        if signer_type == SignerType.ECDSA:
            signer = SignerECDSA()
        else:
            # default type
            signer = SignerRSA()
        signer.from_private_key(private_key, subtype)
        return signer

    @classmethod
    def from_full_info(cls, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       signer_type: SignerType=SignerType.RSA, subtype: SignerSubType=SignerSubType.MAINNET_REGULAR,
                       verify: bool=True) -> Signer:
        pass

    @classmethod
    def address_to_signer(cls, address: str) -> Signer:
        if RE_RSA_ADDRESS.match(address):
            return SignerRSA
        elif RE_ECDSA_ADDRESS.match(address):
            return SignerECDSA
        raise ValueError("Unsupported Address type")

    @classmethod
    def from_seed(cls, seed: str='', signer_type: SignerType=SignerType.RSA,
                  subtype: SignerSubType=SignerSubType.MAINNET_REGULAR) -> Signer:
        if seed == '':
            seed = urandom(32).hex()
        # TODO: dict instead of all this, 3 lines
        if signer_type == SignerType.RSA:
            signer = SignerRSA()
            signer.from_seed(seed, subtype)
            return signer
        elif signer_type == SignerType.ECDSA:
            signer = SignerECDSA()
            signer.from_seed(seed, subtype)
            return signer
        elif signer_type == SignerType.BTC:
            signer = SignerBTC()
            signer.from_seed(seed, subtype)
            return signer
        elif signer_type == SignerType.CRW:
            signer = SignerCRW()
            signer.from_seed(seed, subtype)
            return signer
        raise ValueError("Unsupported Key type")

    @classmethod
    def verify_bis_signature(cls, signature: str, public_key: str, buffer: bytes, address: str) -> None:
        """Verify signature from bismuth tx network format"""
        # Find the right signer class
        verifier = cls.address_to_signer(address)
        # let it do the job
        verifier.verify_bis_signature(signature,public_key, buffer, address)

