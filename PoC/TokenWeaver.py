from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
 
from os import urandom

from rsabssa import rsabssa_blind, rsabssa_blind_sign, rsabssa_finalize, rsa_pss_verify



### Signature utilities ###

sLen=0

def blind(public_key,msg):
    blinded_msg,inv = rsabssa_blind(public_key,msg,sLen,None,None)
    return blinded_msg,inv

def sign(secret_key,blinded_msg):
    return rsabssa_blind_sign(secret_key, blinded_msg)

def unblind(public_key,blind_sig,inv,msg):
    return rsabssa_finalize(public_key, blind_sig, inv, msg, sLen)

def verify(public_key,sig,msg):
    rsa_pss_verify(public_key, sig, msg, sLen)

### TEE definition ###
class TEE:
    def __init__(self, pkP, pkA, SN, linkable_token):
        # Provisioning and Attestation public keys
        self.pkP = pkP
        self.pkA = pkA
        # TEE SN linked key pair
        self.skSN = RSA.generate(2048)
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
        blinded_token, skB = blind(self.pkP,token)
        self.temp_skB = skB
        self.temp_token = token
        return (self.SN, blinded_token, self.linkable_token)

    def unlinkable_chain_finalize(self, msg):
        # linkable chain step of 5.1, and processing of message 2 of Figure 1        
        linkable_token, blinded_sig = msg
        token_sig = unblind(self.pkP, blinded_sig, self.temp_skB, self.temp_token)
        self.unlinkable_token = (self.temp_token, token_sig)
        self.linkable_token = linkable_token

    def ac_provisioning_init(self):
        # AC provisioning of section 5.3, and sending message 1 of Figure 2.
        # Generate new local attestation key pair
        self.skT = RSA.generate(2048)
        self.pkT = self.skT.public_key()
        blind_pkT, skBT = blind(self.pkA, self.pkT.export_key())
        self.temp_skBT = skBT
        
        # Generate a new blinded token
        token = urandom(32)
        blinded_token,skB = blind(self.pkP, token)
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
        pkT_sig = unblind(self.pkA, blinded_pkT_sig, self.temp_skBT, self.pkT.export_key())
        self.pkT_signed = pkT_sig


    def attest(self):
        msg = SHA256.new(b'attested text')
        signer = PKCS1_PSS.new(self.skT)
        signature = signer.sign(msg)
        return (signature, self.pkT.export_key(), self.pkT_signed)
   
### Provider Definition ###
    
class Provider:
    def __init__(self):
         # Provisioning key pair
        self.skP = RSA.generate(2048)
        self.pkP = self.skP.public_key()
        # Attestation key pair
        self.skA = RSA.generate(2048)
        self.pkA = self.skA.public_key()
        # TEE authentication list
        self.TEE_list = set()
        # Valid linkable tokens
        self.linkable_tokens = set()
        # Deprecated unlinkable tokens
        self.unlinkable_tokens = set()        

    def new_tee(self, SN):
        # Set-up specified in 5.1
        linkable_token = urandom(32)
        new_TEE = TEE(self.pkP,self.pkA,SN,linkable_token)
        self.linkable_tokens.add( (SN,linkable_token) )
        return new_TEE
    
    def unlinkable_chain_request(self, msg):
        #  linkable step of 5.2, provider step, also correspond to message 2 of Figure 1
        SN, blinded_token, linkable_token = msg
        self.linkable_tokens.remove( (SN,linkable_token)) # will raise KeyError and block if invalid token
        new_linkable_token = urandom(32)       
        self.linkable_tokens.add( (SN,new_linkable_token) )
        blinded_sig = sign(self.skP,blinded_token)
        return (new_linkable_token,blinded_sig)

    def ac_provisioning_request(self, msg):
        # AC provisioning of section 5.3, as well as message 2 of Figure 2
        (blinded_token, (unlinkable_token, unlinkable_token_sig), blinded_pkT) = msg

        # Check validity of unlinkable authentication
        # First, check if the unlinkable token is not deprecated
        if not(unlinkable_token in self.unlinkable_tokens):
            # we then check its signature
            verify(self.pkP,unlinkable_token_sig,unlinkable_token)
            # Exception ValueError raised if incorrect token

            # Everything is good; we then perform the two signatures
            blinded_token_sig = sign(self.skP, blinded_token) 
            blinded_pkT_sig = sign(self.skA, blinded_pkT)

            return (blinded_token_sig, blinded_pkT_sig)

### Third Party
class TTP:
    def __init__(self,pkA):
         # Attestation public key 
        self.pkA = pkA

    def check(self,msg):       
        (signature, pkT, pkT_signed) = msg
        verify(self.pkA, pkT_signed, pkT)
        verifier = PKCS1_PSS.new(RSA.importKey(pkT))
        print("Attestation check is %s" % verifier.verify(SHA256.new(b'attested text'), signature))

        
        
# Simulate several protocol run
provider = Provider()
print("Provider initialized.")
      
# Create TEE with SN=1
tee = provider.new_tee(1)
print("New TEE initialized with linkable token.")

# Run one step of the unlinkable initialization chain
imsg1 = tee.unlinkable_chain_init()
imsg2 = provider.unlinkable_chain_request(imsg1)
tee.unlinkable_chain_finalize(imsg2)
print("Linkable token consumed to initialize unlinkable token chain.")

# Run AC multiple times
for i in range(1,3):
    ACmsg1 = tee.ac_provisioning_init()
    ACmsg2 = provider.ac_provisioning_request(ACmsg1)
    tee.ac_provisioning_finalize(ACmsg2)
    print("Unlinkable AC provisioning performed.")

# Run one step of the unlinkable initialization chain
imsg1 = tee.unlinkable_chain_init()
imsg2 = provider.unlinkable_chain_request(imsg1)
tee.unlinkable_chain_finalize(imsg2)
print("Linkable token consumed to re-initialize unlinkable token chain.")

# Run AC multiple times
for i in range(1,3):
    ACmsg1 = tee.ac_provisioning_init()
    ACmsg2 = provider.ac_provisioning_request(ACmsg1)
    tee.ac_provisioning_finalize(ACmsg2)
    print("Unlinkable AC provisioning performed.")


# Create TTP, given the pkA)
ttp = TTP(provider.pkA)

# make TEE attest
attestmsg=tee.attest()
# TTP check attest
ttp.check(attestmsg)
