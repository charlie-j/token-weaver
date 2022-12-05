# PoC

The TokenWeaver.py scripts implements both the unlinkable and linkable updates, and contain a small simulation of an execution. The protocol implementation takes under 100 lines of codes, comment included.

We use as blind signatures the RSA_BSSA proposal, under standardization at IETF with a proof of concept implementation at https://github.com/cfrg/draft-irtf-cfrg-blind-signatures/blob/main/poc/rsabssa.py, included in this repository. The security of this scheme is proven in https://eprint.iacr.org/2022/895.

# Execution

First install the cryptographic library through

$ pip3 install -U PyCryptodome

Then, simply execute the script with:

$ python3 TokenWeaver.py

