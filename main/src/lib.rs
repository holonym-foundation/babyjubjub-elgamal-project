use num_bigint::{BigInt};
use num_traits::{ToPrimitive, FromPrimitive};
use babyjubjub_rs::{Fr, Fl, Point, ElGamalEncryption, B8, FrBigIntConversion};
use polynomial::Polynomial;
use crate::polynomial::lagrange_basis_at_0;
use ff::{Field};

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
multiplying C1 by their keyshare to get decryption share A(i)*C1

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

    // /// C1 is the first value of the (C1, C2) ElGamal encryption result
    // pub fn partial_decrypt(&self, c1: &Point) -> Point {
    //     // Make sure inputs aren't bad (i imagine this check could be skipped for performance reasons, but it seems a sanity check here would be helpful)
    //     assert!(c1.on_curve());
    //     c1.mul_scalar(&self.share)
    // }
}


/// Node representing a party that can do distributed key generation, store their key share, and calculate a decryption share of a ciphertext using their keyshare 
pub struct Node {
    /// which number node is it. Starts at 1, not 0, as node 0 doesn't exist. If it did, it would know the secret polynomial evaluated at 0, which is the secret key
    idx: usize, 
    /// how many nodes will be needed to decrypt, so that this node knows what degree of polynomial it can decrypt
    threshold_nodes: usize, 
    /// how many nodes there will be total, so that this node knows how many parties to do key generation with
    total_nodes: usize, 
    /// polynomial used to generate the distributed key
    keygen_polynomial: Polynomial,
    /// `keygen_polynomial`'s evaluation at 0 (used to generate the distributed key)
    keygen_polynomial_at_0: BigInt,
    /// share of the decryption key
    keyshare: Option<PrivateKeyShare>
}

// Stores a secret number designated for a particular node
pub struct KeygenHelper {
    for_node: usize,
    value: BigInt
}

impl Node {
    /// Creates a Node using a random keygen polynomial
    /// degree is degree of the polynomial
    pub fn init_rnd(idx: usize, threshold_nodes: usize, total_nodes: usize) -> Node {
        assert!(idx>0 && idx<=total_nodes, "node index {} must be greater than 0 and <= total_nodes {}", idx, total_nodes);
        let kp = Polynomial::random_polynomial_fl(threshold_nodes-1);
        let at_zero = kp.eval(
            &BigInt::from_u8(0).unwrap()
        );
        Node::init(idx, kp, total_nodes)
    }
    /// Creates a Node using a given keygen Polynomial
    pub fn init(idx: usize, polynomial: Polynomial, total_nodes: usize) -> Node {
        assert!(idx>0, "node index {} must be > 0", idx);
        let at_zero = polynomial.eval(
            &BigInt::from_u8(0).unwrap()
        );
        Node {
            idx: idx,
            threshold_nodes: polynomial.deg() + 1,
            total_nodes: total_nodes,
            keygen_polynomial: polynomial,
            keygen_polynomial_at_0: at_zero,
            keyshare: None
        }
    }
    /// num_nodes = how many nodes it needs to share its polynomial evaluations with. Note: all nodes must do this and give result to all other nodes
    pub fn keygen_step1(&self, num_nodes: usize) -> Vec<KeygenHelper> {
        (0..num_nodes).map(
            |i| {
                let idx = i + 1; // i+1 since nodes are indexed at 1
                KeygenHelper {
                    for_node: idx, 
                    value: self.keygen_polynomial.eval(&BigInt::from_usize(idx).unwrap())
                } 
            }
        )

        .collect::<Vec<KeygenHelper>>()
    }

    /// sets node i's keyshare of as A(i) where A is the secret polynomial. It does this by summing the evaluation of all the other nodes' keygen polynomials at i. 
    /// The other nodes have to send node i their keygen polynomial at i. These other polynomials are other_keygens_for_me
    /// i isn' 0-indexed; it's 1-indexed.
    pub fn set_keyshare(&mut self, keygen_evals_at_i: &Vec<&KeygenHelper>) {
        assert!(keygen_evals_at_i.len() == self.total_nodes, "Error setting keyshare: not enough keygen polynomial evaluations at i! One evaluation is needed from *every* node:  {} evaluations provided but {} are required", keygen_evals_at_i.len(), self.total_nodes);
        let _ = keygen_evals_at_i.iter().for_each(
            |kh| assert!(kh.for_node == self.idx, "Error setting keyshare: recieved an evaluation of a keygen polynomial at some value other than i")
        );
        let keygen_sums_at_i: BigInt = keygen_evals_at_i.iter().map(
            |kh| &kh.value
        ).sum();

        self.keyshare = Some(
            PrivateKeyShare { share: keygen_sums_at_i }
        );
    }

    pub fn pubkey_share(&self) -> Point {
        B8.mul_scalar(&self.keygen_polynomial_at_0)
    }

    /// Return this node's secret share * this node's Lagrange basis, evaluated at 0. All nodes' secret_lagrange_basis_at_0() should sum to the shared private key
    fn secret_lagrange_basis_at_0(&self) -> Fl {
        let mut basis = lagrange_basis_at_0(self.idx as u32, self.threshold_nodes as u32);
        basis.mul_assign(&Fl::from_bigint(&self.keyshare.as_ref().unwrap().share));
        basis
    }

    // /// Performs a partial decryption on C1 of the ElGamal encrypted value (C1, C2). Returns secret share * C1
    // pub fn partial_decrypt_(&self, c1: &Point) -> Point {
    //     self.keyshare.as_ref().unwrap()
    //     .partial_decrypt(c1)
    // }

    /// Performs a partial decryption on C1 of the ElGamal encrypted value (C1, C2). Returns secret share * my lagrange basis * C1
    pub fn partial_decrypt(&self, c1: &Point) -> Point {
        c1.mul_scalar(&self.secret_lagrange_basis_at_0().to_bigint())
    }

    

}



/* Functions to help encrypt to nodes and decrypt from nodes. Adds their pubkeys shares */
pub fn calculate_pubkey(pubkey_shares: Vec<Point>) -> Option<Point> {
    let mut acc: Option<Point> = None;
    for point in pubkey_shares.iter() {
        match acc {
            None => acc = Some(point.clone()),
            Some(_) => acc = Some(acc.unwrap().add(point))
        }
    }
    acc
}

// pub fn decrypt_(encrypted: ElGamalEncryption, shares: Vec<Point>, num_shares_needed: u64) -> Point {
//     assert!(shares.len().to_u64().unwrap() >= num_shares_needed);
//     let reconstructed_bases_at_0 = shares.iter().enumerate().map(
//         // Now we have a mapping of index i to decryption share s_i
//         // Multiply the ith Lagrange basis at 0, L_i(0), by s_i 
//         |(i, s_i)| 
//         s_i.mul_scalar(
//             &lagrange_basis_at_0((i+1) as u32, (num_shares_needed - 1) as u32).to_bigint()
//         )
//     );

//     // Sum all the reconstructed bases at 0 to get the y-intercept
//     let reconstructed_polynomial_at_0 = reconstructed_bases_at_0.reduce(
//         |a,b| a.add(&b)
//     ).unwrap();
    
//     // The Diffie-Hellman "shared secret" in ElGamal system coincides with reconstructed "shared secret" at y-intercept, even though these are shared in different ways!
//     encrypted.c2.add(&reconstructed_polynomial_at_0.neg())
// }


// Reconstructs the Diffie-Hellman shared secret using decryption shares
pub fn reconstruct_dh_secret(decryption_shares: Vec<Point>) -> Point {
    decryption_shares.iter().map(|x|x.clone()).reduce(
        |a,b| a.add(&b)
    ).unwrap()
}

pub fn decrypt(encrypted: ElGamalEncryption, shares: Vec<Point>, num_shares_needed: u64) -> Point {
    assert!(shares.len().to_u64().unwrap() == num_shares_needed);

    let reconstructed_dh_secret = reconstruct_dh_secret(shares);

    // The Diffie-Hellman "shared secret" in ElGamal system coincides with reconstructed "shared secret" at y-intercept, even though these are shared in different ways!
    encrypted.c2.add(&reconstructed_dh_secret.neg())
}


#[cfg(test)]
mod tests {
    use std::{vec, ops::{Add, Mul}, result};

    use babyjubjub_rs::{encrypt_elgamal, Q};
    use num_bigint::ToBigInt;

    use super::*;

    #[test]
    fn test_pubkey() {
        let node1 = Node::init_rnd(1,2, 2);
        let node2 = Node::init_rnd(2,2, 2);

        let shared_pubkey = calculate_pubkey(
            vec![node1.pubkey_share(), node2.pubkey_share()]
        ).unwrap();
        // since this test can access private variables, lets see whether the pubkey is correct:
        let secret_key_nobody_knows = node1.keygen_polynomial_at_0 + node2.keygen_polynomial_at_0;
        
        assert!(shared_pubkey.equals(B8.mul_scalar(&secret_key_nobody_knows)));
        // node1.pubkey_share(num_nodes)
    }
    // Check the secret can indeed be reconstructed from the shares (this won't happen if the nodes follow protocol, but should be tested that it *can* happen, because if it can't happen, the key was generated incorrectly)
    #[test]
    fn test_keygen() {
        let mut nodes = vec![
            Node::init_rnd(1,3,3),
            Node::init_rnd(2,3,3),
            Node::init_rnd(3,3,3),

        ];


        let secret_polynomial_nobody_knows = nodes.iter().fold(
            Polynomial::from_coeffs(
                vec![0.to_bigint().unwrap(), 0.to_bigint().unwrap(), 0.to_bigint().unwrap()]
            ),
            |a,b| a.add_same_deg(&b.keygen_polynomial)
        );

        // do keygen process
        let keygen_helpers: Vec<Vec<KeygenHelper>> = nodes.iter().map(|node| node.keygen_step1(3)).collect();

        let node1_inputs: Vec<&KeygenHelper> = keygen_helpers.iter().map(
            |outputs| &outputs[0]
        ).collect();
        let node2_inputs: Vec<&KeygenHelper> = keygen_helpers.iter().map(
            |outputs| &outputs[1]
        ).collect();
        let node3_inputs: Vec<&KeygenHelper> = keygen_helpers.iter().map(
            |outputs| &outputs[2]
        ).collect();

        nodes[0].set_keyshare(&node1_inputs); 
        nodes[1].set_keyshare(&node2_inputs); 
        nodes[2].set_keyshare(&node3_inputs); 

        nodes.iter().for_each(
            |n| 
            assert_eq!(
                secret_polynomial_nobody_knows.eval(&n.idx.to_bigint().unwrap()),
                n.keyshare.as_ref().unwrap().share
            )
        )

    }
    #[test]
    fn test_partial_decryption() {
        let mut node1 = Node::init_rnd(1,3, 3);
        let mut node2 = Node::init_rnd(2,3, 3);
        let mut node3 = Node::init_rnd(3,3, 3);

        // simulate keygen process:
        // The nodes sharing one of their evaluations with the other nodes
        let from_node1 = node1.keygen_step1(3);
        let from_node2 = node2.keygen_step1(3);
        let from_node3 = node3.keygen_step1(3);
        // Remember to subtract one from the index to conver it to zero-index!
        let to_node1 = vec![&from_node1[0], &from_node2[0], &from_node3[0]];
        let to_node2 = vec![&from_node1[1], &from_node2[1], &from_node3[1]];
        let to_node3 = vec![&from_node1[2], &from_node2[2], &from_node3[2]];
        // and finally each node reconstructs their part of the secret
        node1.set_keyshare(&to_node1);
        node2.set_keyshare(&to_node2);
        node3.set_keyshare(&to_node3);
        
        let secret_key_nobody_knows = 
            node1.keygen_polynomial_at_0.clone() + 
            node2.keygen_polynomial_at_0.clone() + 
            node3.keygen_polynomial_at_0.clone() ;


        // some arbitrary nonce and public version
        let nonce = &7654321.to_bigint().unwrap();
        let public_nonce = B8.mul_scalar(nonce);

        // Try decrypting
        let d1 = node1.partial_decrypt(&public_nonce);
        let d2 = node2.partial_decrypt(&public_nonce);
        let d3 = node3.partial_decrypt(&public_nonce);
        
        //[nonce * L_i(0)] B8
        let d1_ = public_nonce.mul_scalar(&node1.secret_lagrange_basis_at_0().to_bigint());
        let d2_ = public_nonce.mul_scalar(&node2.secret_lagrange_basis_at_0().to_bigint());
        let d3_ = public_nonce.mul_scalar(&node3.secret_lagrange_basis_at_0().to_bigint());

        assert!(d1.equals(d1_));
        assert!(d2.equals(d2_));
        assert!(d3.equals(d3_));

        // Note: this is full decryption and should perhaps be in another file:
        let modulus =  BigInt::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",10
        )
            .unwrap();

        // Can ignore this; secret key hasd been above modulus regardless of wheter the test succeeds!
        // println!(
        //     "secret key is under modulus? \n {:?} \n {:?}", secret_key_nobody_knows, modulus
        // );

        
        // println!("LHS\n{:?}\nRHS\n{:?}", d1.add(&d2).add(&d3), B8.mul_scalar(&(secret_key_nobody_knows)).mul_scalar(&nonce));
        
        // Delete this part when test working. It just shows that the Lagrange interpolation correctly recovered the secret. However, Lagrange interpolation over elliptic curve is failing half of the time in the next asssert.
        let secret_key_nobody_knows = 
            node1.keygen_polynomial_at_0.clone() + 
            node2.keygen_polynomial_at_0.clone() + 
            node3.keygen_polynomial_at_0.clone() ;
        
        let mut result = node1.secret_lagrange_basis_at_0();
        result.add_assign(  &node2.secret_lagrange_basis_at_0());
        result.add_assign(  &node3.secret_lagrange_basis_at_0());
        
        assert!(result.eq(&Fr::from_bigint(&secret_key_nobody_knows)));
        
        // Why doesn't this work? Shouldn't it wrap around or give the special point?
        // println!("B8? {:?} {:?} \n {:?} {:?}", B8.x, B8.y, B8.mul_scalar(&(modulus.clone())).x, B8.mul_scalar(&(modulus.clone())).y);
        // THIS LINE WORKS HALF OF THE TIME????
        assert!(d1.add(&d2).add(&d3).equals(
            B8.mul_scalar(&(secret_key_nobody_knows)).mul_scalar(&nonce)
        ));

        assert!(d1.add(&d2).add(&d3).equals(
            B8.mul_scalar(&nonce).mul_scalar(&(secret_key_nobody_knows))
        ));

    }

    // This is again behavior that should not happen in the wild but should be possible if protocol is deviated. If it is impossible for this particular devation  from the protocol, the code must be wrong. Hence, we test that it's possible to reconstruct the shared secret from these functions:
    #[test]
    fn test_langrage_interpolate_for_shared_secret() {
        let mut node1 = Node::init_rnd(1,3, 3);
        let mut node2 = Node::init_rnd(2,3, 3);
        let mut node3 = Node::init_rnd(3,3, 3);
        
        // simulate the nodes sharing one of their evaluations with the other nodes 
        let from_node1 = node1.keygen_step1(3);
        let from_node2 = node2.keygen_step1(3);
        let from_node3 = node3.keygen_step1(3);
        // Remember to subtract one from the index to conver it to zero-index!
        let to_node1 = vec![&from_node1[0], &from_node2[0], &from_node3[0]];
        let to_node2 = vec![&from_node1[1], &from_node2[1], &from_node3[1]];
        let to_node3 = vec![&from_node1[2], &from_node2[2], &from_node3[2]];
        // and finally each node reconstructs their part of the secret
        node1.set_keyshare(&to_node1);
        node2.set_keyshare(&to_node2);
        node3.set_keyshare(&to_node3);

        
        let secret_key_nobody_knows = 
            node1.keygen_polynomial_at_0.clone() + 
            node2.keygen_polynomial_at_0.clone() + 
            node3.keygen_polynomial_at_0.clone() ;
        
        let mut result = node1.secret_lagrange_basis_at_0();
        result.add_assign(  &node2.secret_lagrange_basis_at_0());
        result.add_assign(  &node3.secret_lagrange_basis_at_0());
        
        assert!(result.eq(&Fr::from_bigint(&secret_key_nobody_knows)), "failed to reconstruct secret key from lagrange bases");

    }

    // TODO: separate this into smaller unit tests
    // TODO: try with more total nodes than threshold nodes
    #[test]
    fn test_keygen_encrypt_decrypt() {
        let mut node1 = Node::init_rnd(1,3, 3);
        let mut node2 = Node::init_rnd(2,3, 3);
        let mut node3 = Node::init_rnd(3,3, 3);
        
        // simulate the nodes sharing one of their evaluations with the other nodes 
        let from_node1 = node1.keygen_step1(3);
        let from_node2 = node2.keygen_step1(3);
        let from_node3 = node3.keygen_step1(3);
        // Remember to subtract one from the index to conver it to zero-index!
        let to_node1 = vec![&from_node1[0], &from_node2[0], &from_node3[0]];
        let to_node2 = vec![&from_node1[1], &from_node2[1], &from_node3[1]];
        let to_node3 = vec![&from_node1[2], &from_node2[2], &from_node3[2]];
        // and finally each node reconstructs their part of the secret
        node1.set_keyshare(&to_node1);
        node2.set_keyshare(&to_node2);
        node3.set_keyshare(&to_node3);

        // Try encrypting a message
        let some_msg = B8.mul_scalar(&123456789.to_bigint().unwrap());
        let shared_pubkey = calculate_pubkey(
            vec![node1.pubkey_share(), node2.pubkey_share(), node3.pubkey_share()]
        ).unwrap();
        let nonce = &7654321.to_bigint().unwrap();
        let public_nonce = B8.mul_scalar(nonce);
        // Check C2 was computed correctly
        let encrypted = encrypt_elgamal(&shared_pubkey, nonce, &some_msg);
        // let secret_key_nobody_knows = &node1.keygen_polynomial_at_0 + &node2.keygen_polynomial_at_0 + &node3.keygen_polynomial_at_0;     

        // // Why is this wrong?
        // assert!(shared_pubkey.equals(B8.mul_scalar(&secret_key_nobody_knows)));

        // assert!(encrypted.c2.equals(
        //     some_msg.add(
        //         &B8.mul_scalar(&secret_key_nobody_knows).mul_scalar(nonce)
        //     )
        // ));
        
        
        let d1 = node1.partial_decrypt(&encrypted.c1);
        let d2 = node2.partial_decrypt(&encrypted.c1);
        let d3 = node3.partial_decrypt(&encrypted.c1);


        let secret_key_nobody_knows = 
            node1.keygen_polynomial_at_0 + 
            node2.keygen_polynomial_at_0 + 
            node3.keygen_polynomial_at_0 ;
        // assert!(B8.mul_scalar(&secret_key_nobody_knows).equals(shared_pubkey), "abcd");

        let mut r1 = lagrange_basis_at_0(1,3);
        r1.mul_assign(&Fr::from_bigint(&node1.keyshare.unwrap().share));
        // let p1 = public_nonce.mul_scalar(&r1.to_bigint());

        let mut r2 = lagrange_basis_at_0(2,3);
        r2.mul_assign(&Fr::from_bigint(&node2.keyshare.unwrap().share));
        // let p2 = public_nonce.mul_scalar(&r2.to_bigint());

        let mut r3 = lagrange_basis_at_0(3,3);
        r3.mul_assign(&Fr::from_bigint(&node3.keyshare.unwrap().share));
        // let p3 = public_nonce.mul_scalar(&r3.to_bigint());

        
        let mut result = r1.clone();
        result.add_assign(&r2);
        result.add_assign(&r3);
        assert!(result.eq(&Fr::from_bigint(&secret_key_nobody_knows)), "failed to reconstruct secret key from lagrange bases");

        let shared_dh_secret = shared_pubkey.mul_scalar(
            &nonce.mul(secret_key_nobody_knows)
        );

        // let mut r1 = lagrange_basis_at_0(1,3);
        // r1.mul_assign(&Fr::from_bigint(&node1.keyshare.unwrap().share));
        // let p1 = public_nonce.mul_scalar(&r1.to_bigint());

        // let mut r2 = lagrange_basis_at_0(2,3);
        // r2.mul_assign(&Fr::from_bigint(&node2.keyshare.unwrap().share));
        // let p2 = public_nonce.mul_scalar(&r2.to_bigint());

        // let mut r3 = lagrange_basis_at_0(3,3);
        // r3.mul_assign(&Fr::from_bigint(&node3.keyshare.unwrap().share));
        // let p3 = public_nonce.mul_scalar(&r3.to_bigint());

        // let result = p1.add(&p2).add(&p3);
        
        // assert!(shared_dh_secret.equals(
        //     result
        // ));
        // assert!(shared_dh_secret.equals(
        //     reconstruct_dh_secret(vec![d1,d2,d3])
        // ));

        // let decrypted = decrypt(encrypted, vec![d1,d2,d3], 3);
        // println!("some_msg {:?}", some_msg);
        // println!("decrypted {:?}", decrypted);
        // assert!(decrypted.equals(some_msg));

    }

}