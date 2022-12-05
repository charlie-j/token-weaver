This folder contains some formal analysis of the unlinkable and linkable token chains, both for Post-Compromise Security (PCS) and privacy. 

This analysis requires:
 * DeepSec for the privacy analysis
 * Tamarin for the PCS proofs

# Privacy analysis

## Unlinkable chain isolation

We model in `AuthorizationToken_priv.dps` the unlinkable token chain. We model two enclaves that have initialized their states to contain a valid unlinkable token, and we model the fact that either of the two can then make a one step authorization, where it both authenticate to the server, as well as renew its unlinkable token.

In this file, we model the two TEEs that are communicating directly with the attacker. As such, the attacker is playing the role of a dishonest server trying to track the TEEs.

Using deepsec, we then prove that a scenario where only a single TEE is performing updates is completely indistinguishable from the scenario where two TEEs are performing updates. DeepSec only works for bounded protocols, we were able to prove this property for up to 16 total updates. 

Verifying the protocol takes for 16 updates around 30 seconds (performances may vary based on the specific hardware used) by running

```
$ deepsec AuthorizationToken_priv.dps
```

## An attack on a draft design

Performing the formal analysis in fact helped us improve the design of the update mechanism. In a first version, the TEE would not in the final step check whether the server did return the signature of the blinded token, or some other malicious value that the server can then use in the next run to track us. This attack was reported by DeepSec on a model without this check, and is illustrated in the file `AuthorizationToken_priv_att.dps`.

DeepSec takes under a second to rediscover the attack with:
```
$ deepsec --trace AuthorizationToken_priv_att.dps 
```

DeepSec's CLI output is however not easy to read, we used the optional GUI to inspect the trace.

## TokenWeaver Analysis

We model in `AC_provisioning.dps` a generalization of the previous model, with the same threat model. It contains the full solution combining two interleaved linkable and unlinkable chains. A linkable chain update is always performed by two TEEs, while an unlinkable one is either performed always by the same one or by the two distinct ones.

Verifying the protocol for 8 linkable and 8 unlinkable updates takes under a minute, while verifying it for 12 of each takes 20 hours.

# Post Compromise analysis

We constructed two models:
 * a first one models the unlinkable token chains in isolation, and we verify that it provides PCS 
 * a second model is of the unlinkable token chain combined with the linkable token chain used to renew the secret signing key used for the unlinkable tokens. We verify over the linkable token chain does provide PCS, and that renewing the key of the unlinkable tokens does forces the attacker to use the linkable token mechanism to keep having unlinkable tokens.

The first model is contained in the file `AuthorizationToken_FS_PCS.spthy`, and can be verified with:
```
$ tamarin-prover AuthorizationToken_FS_PCS.spthy --prove +RTS -N8 -RTS
 ```
 (this commands forbids to use more than 8 cores, as it is usually not efficient for Tamarin to use more than that)
 This verifies in about 10 seconds. The proof required 8 helping lemmas in order to prove the PCS lemma, and three proofs were not automated but are stored, for a total of 76 + 88 + 10 steps.
 
The second model is in the file `AC_provisioning.spthy`, and is verified in about 20 seconds with:

```
$ tamarin-prover AC_provisioning.spthy --prove +RTS -N8 -RTS
```
This proof, with a more complex models, required a total of 19 lemmas, two of them being the targeted properties. 5 of them required manual proofs, for a total number of 148+105+27+64+40+122 steps.
