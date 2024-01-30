from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import DSS, pss
from Crypto.Hash import SHA256

from os import urandom

from rsabssa import rsabssa_blind, rsabssa_blind_sign, rsabssa_finalize, rsa_pss_verify

from ProviderStore import LinkableTokens, UnlinkableTokens

from timeit import default_timer as timer

### Signature utilities ###

sLen = 0


def blind(public_key, msg):
    blinded_msg, inv = rsabssa_blind(public_key, msg, sLen, None, None)
    return blinded_msg, inv


def sign(secret_key, blinded_msg):
    return rsabssa_blind_sign(secret_key, blinded_msg)


def unblind(public_key, blind_sig, inv, msg):
    return rsabssa_finalize(public_key, blind_sig, inv, msg, sLen) # Note that `rsabssa_finalize` also verifies the unblinded signature


def verify(public_key, sig, msg):
    rsa_pss_verify(public_key, sig, msg, sLen)
    
def sign_standard(secret_key, msg):
    signer = pss.new(secret_key)
    return signer.sign(SHA256.new(msg)) 


### TEE definition ###
class TEE:
    def __init__(self, pkP, pkA, SN, linkable_token):
        # Provisioning and Attestation public keys
        self.pkP = pkP
        self.pkA = pkA
        # TEE SN linked key pair
        self.skSN = ECC.generate(curve='P-256')
        self.pkSN = self.skSN.public_key()
        # Serial Number
        self.SN = SN
        # Linkable token
        self.linkable_token = linkable_token
        # Unlinkable token
        self.unlinkable_token = None

    def unlinkable_chain_init(self):
        # linkable chain step of 5.1, and message 1 of Figure 1
        token = urandom(32)
        blinded_token, skB = blind(self.pkP, token)
        self.temp_skB = skB
        self.temp_token = token
        return (self.SN, blinded_token, self.linkable_token, self.pkSN.export_key(format='raw'))

    def unlinkable_chain_finalize(self, msg):
        # linkable chain step of 5.1, and processing of message 2 of Figure 1
        linkable_token, blinded_sig, sig_pkSN = msg
        token_sig = unblind(self.pkP, blinded_sig, self.temp_skB, self.temp_token)
        self.unlinkable_token = (self.temp_token, token_sig)
        self.linkable_token = linkable_token
        self.sig_pkSN = sig_pkSN

    def ac_provisioning_init(self):
        # AC provisioning of section 5.3, and sending message 1 of Figure 2.
        # Generate new local attestation key pair
        self.skT = ECC.generate(curve='P-256')
        self.pkT = self.skT.public_key()
        blind_pkT, skBT = blind(self.pkA, self.pkT.export_key(format='raw'))
        self.temp_skBT = skBT

        # Generate a new blinded token
        token = urandom(32)
        blinded_token, skB = blind(self.pkP, token)
        self.temp_skB = skB
        self.temp_token = token

        return (blinded_token, self.unlinkable_token, blind_pkT)

    def ac_provisioning_finalize(self, msg):
        # AC provisioning of section 5.3, and processing message 2 of Figure 2.

        (blinded_token_sig, blinded_pkT_sig) = msg

        # Unblind and store new unlinkable token
        token_sig = unblind(self.pkP, blinded_token_sig, self.temp_skB, self.temp_token)
        self.unlinkable_token = (self.temp_token, token_sig)

        # Process and store new AC
        pkT_sig = unblind(
            self.pkA, blinded_pkT_sig, self.temp_skBT, self.pkT.export_key(format='raw')
        )
        self.pkT_signed = pkT_sig

    def attest(self):
        msg = SHA256.new(b"attested text")
        signer = DSS.new(self.skT, 'fips-186-3')
        signature = signer.sign(msg)
        return (signature, self.pkT.export_key(format='raw'), self.pkT_signed)


### Provider Definition ###
class Provider:
    def __init__(self):
        # Provisioning key pair
        self.skP = RSA.generate(2048)
        self.pkP = self.skP.public_key()
        # Attestation key pair
        self.skA = RSA.generate(2048)
        self.pkA = self.skA.public_key()
        # Valid linkable tokens
        self.linkable_tokens = LinkableTokens()
        # Deprecated unlinkable tokens
        self.unlinkable_tokens = UnlinkableTokens()

    def new_tee(self, SN):
        # Set-up specified in 5.1
        linkable_token = urandom(32)
        new_TEE = TEE(self.pkP, self.pkA, SN, linkable_token)
        self.linkable_tokens.add(SN, linkable_token)
        return new_TEE

    def unlinkable_chain_request(self, msg):
        #  linkable step of 5.2, provider step, also correspond to message 2 of Figure 1
        SN, blinded_token, linkable_token, pkSN = msg
        
        new_linkable_token = urandom(32)
        db_s = timer()
        stored_lt = self.linkable_tokens.get(SN)
        if stored_lt is None or stored_lt != linkable_token:
            raise KeyError()
        self.linkable_tokens.update(SN, new_linkable_token)
        db_e = timer()

        crypt_s = timer()
        blinded_sig = sign(self.skP, blinded_token)
        sig_pkSN = sign_standard(self.skA, pkSN)
        crypt_e = timer()
        return ((new_linkable_token, blinded_sig, sig_pkSN), db_e - db_s, crypt_e - crypt_s)

    def ac_provisioning_request(self, msg):
        # AC provisioning of section 5.3, as well as message 2 of Figure 2
        (blinded_token, (unlinkable_token, unlinkable_token_sig), blinded_pkT) = msg

        # Check validity of unlinkable authentication
        # First, check if the unlinkable token is not deprecated
        db_s1 = timer()
        token_in_db = unlinkable_token in self.unlinkable_tokens
        db_e1 = timer()
        if not token_in_db:
            crypt_s1 = timer()
            # we then check its signature
            verify(self.pkP, unlinkable_token_sig, unlinkable_token)
            # Exception ValueError raised if incorrect token
            crypt_e1 = timer()

            db_s2 = timer()
            self.unlinkable_tokens.add(unlinkable_token)
            db_e2 = timer()

            crypt_s2 = timer()
            # Everything is good; we then perform the two signatures
            blinded_token_sig = sign(self.skP, blinded_token)
            blinded_pkT_sig = sign(self.skA, blinded_pkT)
            crypt_e2 = timer()

            db_t = (db_e1 - db_s1) + (db_e2 - db_s2)
            crypt_t = (crypt_e1 - crypt_s1) + (crypt_e2 - crypt_s2)

            return ((blinded_token_sig, blinded_pkT_sig), db_t, crypt_t)


### Third Party
class TTP:
    def __init__(self, pkA):
        # Attestation public key
        self.pkA = pkA

    def check(self, msg):
        (signature, pkT, pkT_signed) = msg
        verify(self.pkA, pkT_signed, pkT)
        verifier = DSS.new(ECC.import_key(pkT, curve_name='P-256'), 'fips-186-3')
        verifier.verify(SHA256.new(b"attested text"), signature) # Raises ValueError if signature is not authentic