"""
Demoes how to verify a generic tx
"""

import json
import sys
sys.path.append('../')
from polysign.signerfactory import SignerFactory

if __name__ == "__main__":
    # Sample real rsa tx
    with open("rsa_tx1.json") as f:
        rsa_tx = json.load(f)

    # Caller is responsible for creating the bin buffer to check the sig against
    buffer = str((rsa_tx['timestamp'], rsa_tx['address'], rsa_tx['recipient'],
                  rsa_tx['amount'], rsa_tx['operation'], rsa_tx['openfield'])).encode("utf-8")
    print("buffer", buffer)

    verifier = SignerFactory.address_to_signer(rsa_tx['address'])
    print("Signer/Verifier class", verifier)
    verifier.verify_bis_signature(rsa_tx['signature'], rsa_tx['public_key'], buffer, rsa_tx['address'])
    print("No Error")
