use num_bigint::{BigInt};
use num_traits::{ToPrimitive, FromPrimitive};
use babyjubjub_rs::{Fr, Point, ElGamalEncryption, B8, FrToBigInt};
use ff::{Field, PrimeField};
use polynomial::Polynomial;
use crate::polynomial::lagrange_basis_at_0;

mod polynomial;

/* 
HOW THIS WORKS
Key generatation pt. 1
----------------------
all `n=d+1` Nodes are nodes that will perform threshold decryption, where d is the degree of the polynomials
that they will all work with. The nodes first agree on a common polynomial, A, that nobody knows. This is DKG,
or distributed key generation.

The DKG process is somewhat simple:
1. All n nodes create a keygen polynomial: A_1, A_2, ... A_n
2. A is the sum of all keygen polynomials

How is the shared public key created, since nobody knows A but rather only their own A_i? Recall a public key in ElGamal is a private key scalar
multiplied by the generator point. In this library, the generator point used is the BabyJubJub base point. 
Let the private key scalar be A(0). The public key is A(0)*B, where B is the base point.

Sounds fine and dandy so far, but how do we calculate A(0)*B? 
1. Each node sends their keygen polynomial evaluated at 0 times the base point, A_i(0)*B. Let's call A_i(0)*B a pubkey share for node i.
2. A(0)*B is just the sum of all pubkey shares

Key generatation pt. 2
-----------------------
Yet A_i is actually not the i'th node's keyshare for decryption. It was only used for generating the keyshares,
but it's not the actual key. As we will soon notice, the keyshare used to decrypt messages is a point on A.
A is the shared polynomial, not the individual polynomial. Node 1 will know A(1). Node 2 will know A(2). Node n will
know A(n). Hence, the actual secret share is not A_i but rather A(i).

How will we construct A(i) such that only node # i knows it? A familiar-ish process:
1. Each node sends their keygen polynomial evaluated at i to node # i
2. Node i then reconstructs A(i) = the sum of all other polynomials A_j(i)
Essentially, the nodes just send their evaluations at point i to node i, then node i sums them to get A(i)

Now each node has A(i), they can use A(i), their decryption share, to decrypt messages together.


Decryption
----------------
Recall ElGamal decryption involves 
1. Calculating a Diffie-Hellman shared secret
2. Subtracting that shared secret from the encrypted message
That's pretty much it. The ciphertext is two points, c1 and c2. 
C1 is r*B, where r is a random nonce used as to make the shared secret.
C2 is m+s, where m is the message to be encrypted and s is the shared secret.
The shared secret is calculated the standard Diffie-Hellman way: p*r*B, where p is the private key of whoever will decrypt it.

Obviously, this doesn't quite work in the threshold method without some modifications -- it relies on a private key, p, that no party knows. 
Here, A(0) is used for p. The secret key is the evaluation of the shared, unknown, polynomial at 0.

To decrypt it, node i sends decryption share A(i)*C1. Note A(i) is a scalar despite A being uppercase

Once enough nodes have sent decryption shares, the polynomial can be reconstructed by modified Lagrange interpolation.

The Lagrange bases for n nodes are polynomials L_i for i=1..n such that
    -    L_i(x) = 1 when x is i
    -    L_i(x) = 0 when x is not i    

A polynomial can be represented as a sum of unique Lagrange bases. Therefore, A can be represented as a weighted sum ∑w*L_i for i=1..n where weight w=A(i)

What's A(0) in terms of Lagrange bases? It is ∑L_i(0)*A(i) for i=1..n
Anyone can compute L_i(0)  easily for any node's i. This is done in a polynomial.rs function
`lagrange_basis_at_0`.


These components can be tied together to decrypt the message by giving decryption shares d_i:
Node i computes d_i via:
multiplying C1 by their decryption key to get decryption share A(i)*C1

Once enough d_i values are learned, one can recover the shared secret. Recall the Diffie-Hellman
shared secret is p*r*B, where p is A(0), the private key of the decryptor. And recall
that C1 is r*B. 

p*r*B = A(0)*r*B
Recall A(0) is ∑L_i(0)*A(i) for i=1..n
p*r*b = ∑L_i(0)*A(i)*C1 for i=1..n
p*r*b = ∑L_i(0)*d_i for i=1..n

There you have it. You've reconstructed the shared secret via only L_i(0) and d_i given nodes i=1..n
once you have the shared secret, you can subtract it from C2 to get the original message.


Encoding/Decoding a message to/from an elliptic curve point
------------------
The message is represented as a point. A variation of the Koblitz encoding method is used in this modifed
babyjubjub-rs library.

*/
pub struct PrivateKeyShare {
    share: BigInt,
}


impl PrivateKeyShare {
    pub fn from_bigint(b: BigInt) -> PrivateKeyShare {
        PrivateKeyShare { share: b }
    }

    pub fn partial_decrypt(&self, encrypted_point: ElGamalEncryption) -> Point {
        // Make sure inputs aren't bad (i imagine this check could be skipped for performance reasons, but it seems a sanity check here would be helpful)
        assert!(encrypted_point.c1.on_curve() && encrypted_point.c2.on_curve());
        encrypted_point.c1.mul_scalar(&self.share)
    }

}


/// Node representing a party that can do distributed key generation, store their key share, and calculate a decryption share of a ciphertext using their keyshare 
pub struct Node {
    /// which number node is it. Starts at 1, not 0, as node 0 doesn't exist. If it did, it would know the secret polynomial evaluated at 0, which is the secret key
    idx: usize, 
    /// how many nodes there will be total, so that this node knows what degree of polynomial it can decrypt
    num_nodes: usize, 
    /// polynomial used to generate the distributed key
    keygen_polynomial: Polynomial,
    /// `keygen_polynomial`'s evaluation at 0 (used to generate the distributed key)
    keygen_polynomial_at_0: BigInt,
    /// share of the decryption key
    decryption_key_share: Option<PrivateKeyShare>
}

// Stores a secret number designated for a particular node
pub struct KeygenHelper {
    for_node: usize,
    value: BigInt
}

impl Node {
    /// Creates a Node using a random keygen polynomial
    /// degree is degree of the polynomial
    pub fn init_rnd(idx: usize, num_nodes: usize) -> Node {
        assert!(idx>0 && idx<=num_nodes, "invalid node index {}", idx);
        let kp = Polynomial::random_polynomial_fr(num_nodes-1);
        let at_zero = kp.eval(
            &BigInt::from_u8(0).unwrap()
        );
        Node {
            idx: idx,
            num_nodes: num_nodes,
            keygen_polynomial: kp,
            keygen_polynomial_at_0: at_zero,
            decryption_key_share: None
        }
    }
    /// Creates a Node using a given keygen Polynomial
    pub fn init(idx: usize, polynomial: Polynomial) -> Node {
        assert!(idx>0 && idx<=polynomial.deg(), "invalid node index {}", idx);
        let at_zero = polynomial.eval(
            &BigInt::from_u8(0).unwrap()
        );
        Node {
            idx: idx,
            num_nodes: polynomial.deg() + 1,
            keygen_polynomial: polynomial,
            keygen_polynomial_at_0: at_zero,
            decryption_key_share: None
        }
    }
    /// num_nodes = how many nodes it needs to share its polynomial evaluations with. Note: all nodes must do this and give result to all other nodes
    pub fn keygen_step1(&self, num_nodes: usize) -> Vec<KeygenHelper> {
        (0..num_nodes).map(
            |i| KeygenHelper {
                for_node: i+1, // i+1 since nodes are indexed at 1
                value: self.keygen_polynomial.eval(&BigInt::from_usize(i).unwrap())
            } 
        )

        .collect::<Vec<KeygenHelper>>()
    }

    /// other_keygens_for_me = the idx'th privkey share from every other node's privkey_shares() result (one-indexed!)
    pub fn set_decryption_share(&mut self, other_keygens_for_me: Vec<BigInt>) {
        let shared_polynomial_at_my_idx: BigInt = other_keygens_for_me.iter().sum();
        self.decryption_key_share = Some(
            PrivateKeyShare { share: shared_polynomial_at_my_idx }
        );
    }

    pub fn pubkey_share(&self) -> Point {
        B8.mul_scalar(&self.keygen_polynomial_at_0)
    }

    

}



/* Functions to help encrypt to nodes and decrypt from nodes */

pub fn calculate_pubkey(pubkey_shares: Vec<Point>) -> Point {
    // TODO: implement this. just add all the pubkey shares
    Point {x:Fr::zero(),y:Fr::zero()}
}
pub fn decrypt(encrypted: ElGamalEncryption, shares: Vec<Point>, num_shares_needed: u64) -> Point {
    assert!(shares.len().to_u64().unwrap() >= num_shares_needed);
    let reconstructed_bases_at_0 = shares.iter().enumerate().map(
        // Now we have a mapping of index i to decryption share s_i
        // Multiply the ith Lagrange basis at 0, L_i(0), by s_i 
        |(i, s_i)| 
        s_i.mul_scalar(
            &lagrange_basis_at_0(i as u32, num_shares_needed as u32).to_bigint()
        )
    );

    // Sum all the reconstructed bases at 0 to get the y-intercept
    let reconstructed_polynomial_at_0 = reconstructed_bases_at_0.reduce(
        |a,b| a.add(&b)
    ).unwrap();
    
    // The Diffie-Hellman "shared secret" in ElGamal system coincides with reconstructed "shared secret" at y-intercept, even though these are shared in different ways!
    encrypted.c2.add(&reconstructed_polynomial_at_0.neg())
}


#[cfg(test)]
mod tests {
    use babyjubjub_rs::encrypt_elgamal;
    use num_bigint::ToBigInt;

    use super::*;

    #[test]
    fn test_pubkey() {
        let node1 = Node::init_rnd(1,2);
        let node2 = Node::init_rnd(2,2);

        // see what public key they all create: 
        let mut shared_pubkey = node1.pubkey_share()
                                        .add(
                                        &node2
                                        .pubkey_share()
        );

        // since this test can access private variables, lets see whether the pubkey is correct:
        let secret_key_nobody_knows = node1.keygen_polynomial_at_0 + node2.keygen_polynomial_at_0;
        
        assert!(shared_pubkey.equals(B8.mul_scalar(&secret_key_nobody_knows)));
        // node1.pubkey_share(num_nodes)
    }

    // TODO: separate this into smaller unit tests
    #[test]
    fn test_keygen_encrypt_decrypt() {
        let mut node1 = Node::init_rnd(1,3);
        let mut node2 = Node::init_rnd(2,3);
        let mut node3 = Node::init_rnd(3,3);
        
        // simulate the nodes sharing one of their evaluations with the other nodes 
        let from_node1 = node1.keygen_step1(3);
        let from_node2 = node2.keygen_step1(3);
        let from_node3 = node3.keygen_step1(3);
        // Remember to subtract one from the index to conver it to zero-index!
        let to_node1 = vec![from_node1[0].value.clone(), from_node2[0].value.clone(), from_node3[0].value.clone()];
        let to_node2 = vec![from_node1[1].value.clone(), from_node2[1].value.clone(), from_node3[1].value.clone()];
        let to_node3 = vec![from_node1[2].value.clone(), from_node2[2].value.clone(), from_node3[2].value.clone()];
        // and finally each node reconstructs their part of the secret
        node1.set_decryption_share(to_node1);
        node2.set_decryption_share(to_node2);
        node3.set_decryption_share(to_node3);

        // Try encrypting a message and see if it's 
        let some_msg = B8.mul_scalar(&123456789.to_bigint().unwrap());
        let mut shared_pubkey = node1.pubkey_share()
                                        .add(
                        &node2.pubkey_share()
                                        .add(
                        &node3.pubkey_share()
                                        )
        );
        let encrypted = encrypt_elgamal(
            &shared_pubkey, 
            &7654321.to_bigint().unwrap(), 
            &some_msg
        );
        let dec
    }

}