"""
Basic tests
"""

import json
import sys
sys.path.append('../')
from polysign.signer import SignerType
from polysign.signerfactory import SignerFactory

# Never to be used for real addresses - from https://en.bitcoin.it/wiki/BIP_0032_TestVectors
TEST_SEED = 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'

if __name__ == "__main__":
    # RSA Test
    with open("rsa1.json") as f:
        wallet = json.load(f)
    rsa_private_key = wallet['Private Key']
    signer = SignerFactory.from_private_key(rsa_private_key, SignerType.RSA)
    # print(signer.to_json())
    assert(signer.to_dict()['address'] == wallet['Address'])

    # ECDSA Test - seed is in fact a 32 byte privkey (random, no constraint)
    signer = SignerFactory.from_seed(TEST_SEED, SignerType.ECDSA)
    print(signer.to_dict())
    assert(signer.to_dict()['address'] == '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')
