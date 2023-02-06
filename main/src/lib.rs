use num_bigint::{BigInt};
use num_traits::{ToPrimitive, FromPrimitive};
use babyjubjub_rs::{Fr, Point, ElGamalEncryption, B8, FrToBigInt};
use ff::{Field, PrimeField};
use polynomial::Polynomial;

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
    keygen_polynomial: Polynomial,
    keygen_polynomial_at_0: BigInt,
    decryption_key_share: Option<PrivateKeyShare>
}

impl Node {
    /// Creates a Node using a random keygen polynomial
    /// degree is degree of the polynomial
    pub fn init_rnd(degree: u32) -> Node {
        let kp = Polynomial::random_polynomial_fr(degree);
        let at_zero = kp.eval(&BigInt::from_u8(0).unwrap());
        Node {
            keygen_polynomial: kp,
            keygen_polynomial_at_0: at_zero,
            decryption_key_share: None
        }
    }
    /// Creates a Node using a given keygen Polynomial
    pub fn init(polynomial: Polynomial) -> Node {
        let at_zero = polynomial.eval(&BigInt::from_u8(0).unwrap());
        Node {
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

    pub fn pubkey_share(&self) -> Point {
        B8.mul_scalar(&self.keygen_polynomial_at_0)
    }

}