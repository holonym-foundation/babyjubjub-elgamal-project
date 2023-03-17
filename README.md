## Notes on Security
- no gaurantees of constant time
- ElGamal homomorphic properties enable the recovery of encrypted messages by an attacker through chosen ciphertext attack:
if the attacker has:
- `e`, the encryption of message `m`
- the ability to retrieve the decryption of an arbitrary forged message
they may find `m`, the original message. Thus, it should be made sure the attacker cannot retrieve the decryption of an arbitrary forged message

TODO: double-check that 
https://link.springer.com/content/pdf/10.1007/3-540-44448-3_3.pdf, especially section 4, doesn't apply given sufficient random padding

## How?

Key generatation pt. 1
----------------------
all `n=d+1` Nodes are nodes that will perform threshold decryption, where d is the degree of the polynomials
that they will all work with. The nodes first agree on a common polynomial, A, that nobody knows. This is DKG,
or distributed key generation.

The DKG process is somewhat simple:
1. All n nodes create a keygen polynomial: `A_1`, `A_2`, ... `A_n`
2. `A` is the sum of all keygen polynomials

How is the shared public key created, since nobody knows `A` but rather only their own `A_i`? Recall a public key in ElGamal is a private key scalar
multiplied by the generator point. In this library, the generator point used is the BabyJubJub base point. 
Let the private key scalar be `A(0)`. The public key is `A(0)*B`, where `B` is the base point.

Sounds fine and dandy so far, but how do we calculate `A(0)*B`? 
1. Each node sends their keygen polynomial evaluated at 0 times the base point, `A_i(0)*B`. Let's call `A_i(0)*B` a pubkey share for node i.
2. `A(0)*B` is just the sum of all pubkey shares

Key generatation pt. 2
-----------------------
Yet `A_i` is actually not the i'th node's keyshare for decryption. It was only used for generating the keyshares,
but it's not the actual key. As we will soon notice, the keyshare used to decrypt messages is a point on `A.`
`A` is the shared polynomial, not the individual polynomial. Node 1 will know `A(1)`. Node 2 will know `A(2)`. Node n will
know `A(n)`. Hence, the actual secret share is not A_i but rather A(i).

How will we construct `A(i)` such that only node `i` knows it? A familiar-ish process:
1. Each node sends their keygen polynomial evaluated at i to node `i`
2. Node i then reconstructs `A(i)` = the sum of all other polynomials `A_j(i)`
Essentially, the nodes just send their evaluations at point `i` to node `i`, then node `i` sums them to get `A(i)`

Now each node has A(i), they can use A(i), their decryption share, to decrypt messages together.


Decryption
----------------
Recall ElGamal decryption involves 
1. Calculating a Diffie-Hellman shared secret
2. Subtracting that shared secret from the encrypted message
That's pretty much it. The ciphertext is two points, `C1` and `C2`. 
`C1` is `r*B`, where `r` is a random nonce used as to make the shared secret.
`C2` is `m+s`, where m is the message to be encrypted and `s` is the shared secret.
The shared secret is calculated the standard Diffie-Hellman way: `p*r*B`, where `p` is the private key of whoever will decrypt it.

Obviously, this doesn't quite work in the threshold method without some modifications -- it relies on a private key, `p`, that no party knows. 
Here, A(0) is used for `p`. The secret key is the evaluation of the shared, unknown, polynomial at 0.

To decrypt it, node `i` sends decryption share `A(i)*C1`. Note `A(i)` is a scalar despite `A` being uppercase

Once enough nodes have sent decryption shares, the polynomial can be reconstructed by modified Lagrange interpolation.

The Lagrange bases for `n` nodes are polynomials `L_i` for `i=1..n` such that
- L_i(x) = 1 when x is i
- L_i(x) = 0 when x is not i    

A polynomial can be represented as a sum of unique Lagrange bases. Therefore, A can be represented as a weighted sum `∑w*L_i` for i=1..n where weight w=A(i)

What's `A(0)` in terms of Lagrange bases? It is `∑L_i(0)*A(i)` for i=1..n
Anyone can compute `L_i(0)` easily for any node's i. This is done in a polynomial.rs function
`lagrange_basis_at_0`.


These components can be tied together to decrypt the message by giving decryption shares `d_i`:
Node `i` computes `d_i` via:
multiplying `C1` by their decryption key to get decryption share `A(i)*C1`

Once enough `d_i` values are learned, one can recover the shared secret. Recall the Diffie-Hellman
shared secret is `p*r*B`, where `p` is `A(0)`, the private key of the decryptor. And recall
that `C1` is `r*B`. 

`p*r*B = A(0)*r*B`

Recall `A(0)` is `∑L_i(0)*A(i) for i=1..n`

`p*r*b = ∑L_i(0)*A(i)*C1` for `i=1..n`

`p*r*b = ∑L_i(0)*d_i` for `i=1..n`


There you have it. You've reconstructed the shared secret via only `L_i(0)` and d_i given nodes `i=1..n`
once you have the shared secret, you can subtract it from C2 to get the original message.


Encoding/Decoding a message to/from an elliptic curve point
------------------
The message is represented as a point. A variation of the Koblitz encoding method is used in this modifed
babyjubjub-rs-with-elgamal library.
