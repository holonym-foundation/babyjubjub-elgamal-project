use num_bigint::{BigInt};
use num_traits::{ToPrimitive, FromPrimitive};
use babyjubjub_rs::{Fr, Point, ElGamalEncryption, B8, FrToBigInt};
use ff::{Field, PrimeField};
use polynomial::Polynomial;
use crate::polynomial::lagrange_basis_at_0;

mod polynomial;


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
    idx: usize, // which number node is it. Starts at 1, not 0, as node 0 doesn't exist. If it did, it would know the secret polynomial evaluated at 0, which is the secret key
    keygen_polynomial: Polynomial,
    keygen_polynomial_at_0: BigInt,
    decryption_key_share: Option<PrivateKeyShare>
}

impl Node {
    /// Creates a Node using a random keygen polynomial
    /// degree is degree of the polynomial
    pub fn init_rnd(idx: usize, degree: usize) -> Node {
        assert!(idx>0 && idx<=degree+1, "invalid node index {}", idx);
        let kp = Polynomial::random_polynomial_fr(degree);
        let at_zero = kp.eval(
            &BigInt::from_u8(0).unwrap()
        );
        Node {
            idx: idx,
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
            keygen_polynomial: polynomial,
            keygen_polynomial_at_0: at_zero,
            decryption_key_share: None
        }
    }
    /// num_nodes = how many nodes it needs to share its keys with. Note: all nodes must do this and give result to all other nodes
    pub fn privkey_shares(&self, num_nodes: usize) -> Vec<(usize, BigInt)> {
        (1..num_nodes).map(
            |i| (i, self.keygen_polynomial.eval(&BigInt::from_usize(i).unwrap()))
        )

        .collect::<Vec<(usize, BigInt)>>()
    }

    // /// other_keygens_for_me = the i'th privkey share from every other node's 
    // pub fn set_decryption_share(&self, other_keygens_for_me: Vec<u) {
       
    // }

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
