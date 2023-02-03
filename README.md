# BabyJubJub ElGamal with option for MPC decryption
## Notes on Security
- no gaurantees of constant time
- ElGamal homomorphic properties enable the recovery of encrypted messages by an attacker through chosen ciphertext attack:
if the attacker has:
- `e`, the encryption of message `m`
- the ability to retrieve the decryption of an arbitrary forged message
they may find `m`, the original message. Thus, it should be made sure the attacker cannot retrieve the decryption of an arbitrary forged message

TODO: double-check that 
https://link.springer.com/content/pdf/10.1007/3-540-44448-3_3.pdf, especially section 4, doesn't apply given sufficient random padding