"""
Test - Generate several random ECDSA Bis addresses of different types
"""

import sys
sys.path.append('../')
from polysign.signer import SignerType, SignerSubType
from polysign.signerfactory import SignerFactory
from os import urandom


if __name__ == "__main__":
    for subtype in SignerSubType:
        print('-', subtype.name)
        for i in range(10):
            pk = urandom(32).hex()
            signer = SignerFactory.from_seed(pk, SignerType.ECDSA, subtype=subtype)
            print(signer.to_dict())
