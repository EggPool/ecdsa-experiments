"""
Test bip32 btc like
"""

from coincurve import PrivateKey, PublicKey
from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError
from bip32utils import BIP32Key
from mnemonic import Mnemonic
import os

# seed = os.urandom(32).hex()
seed = '8950b1cffcd85b6ad992feed179863da032b2674178127150db25f5208ea8e4a'
# TEST ONLY, DO NOT USE FOR REAL
print(seed)
pk = PrivateKey.from_hex(seed)
pkhex = pk.to_hex()
print("pkhex", pkhex) # == SEED

key = BIP32Key.fromEntropy(seed.encode('utf-8'))
private_key = key.PrivateKey().hex()
extended_key = key.ExtendedKey()

public_key = key.PublicKey().hex()
address = key.Address()

print("private_key", private_key)
print("extended_key", extended_key)
print("public_key", public_key)
print("address", address)
identifier = key.Identifier().hex()
print("id", identifier)

priv= 'd5ba601c19bfc54e109d20736453ba150f624ee03e2b7a5a3875342cd64d2efe'
pk2 = PrivateKey.from_hex(priv)
pub2 = pk2.public_key.format(compressed=False).hex()
pub2c = pk2.public_key.format(compressed=True).hex()  # This one is used
print("pub2", pub2)
print("pub2c", pub2c)

