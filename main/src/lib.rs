use num_bigint::{BigInt};
use num_traits::{ToPrimitive};
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

    pub fn public(&self) -> Point {
        B8.mul_scalar(&self.share)
    }

    pub fn partial_decrypt(&self, encrypted_point: ElGamalEncryption) -> Point {
        // Make sure inputs aren't bad (i imagine this check could be skipped for performance reasons, but it seems a sanity check here would be helpful)
        assert!(encrypted_point.c1.on_curve() && encrypted_point.c2.on_curve());
        encrypted_point.c1.mul_scalar(&self.share)
    }

}

pub struct DecryptorNode {
    polynomial: Polynomial,

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
