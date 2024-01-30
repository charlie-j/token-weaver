# PoC

The TokenWeaver.py script implements both the unlinkable and linkable updates, and contains a small simulation of an execution. The protocol implementation takes under 100 lines of codes, comments included.

We use as blind signatures the RSA_BSSA proposal, under standardization at IETF with a proof of concept implementation at https://github.com/cfrg/draft-irtf-cfrg-blind-signatures/blob/main/poc/rsabssa.py, included in this repository.
The only change is the use of GMP's modular exponentiation instead of Python's `pow()`.
The security of this scheme is proven in https://eprint.iacr.org/2022/895.

The TokenWeaver_database.py script uses a real database, instead of an in-memory Python `set()`.
The database operations are implemented in `ProviderStore.py`. The databases used in the experiments
were generated using the `generate_db.py` script. The data was collected using the `benchmark.py` script.

# Execution

First install the dependencies through

$ pip3 install -U PyCryptodome gmpy2 tqdm

Then, simply execute the script with:

$ python3 TokenWeaver.py

