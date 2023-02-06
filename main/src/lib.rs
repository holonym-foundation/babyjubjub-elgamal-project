use num_bigint::{BigInt,Sign};
use num_traits::{Num, ToPrimitive};
use babyjubjub_rs::{POSEIDON, Fr, Point, PrivateKey, blh, Signature, ElGamalEncryption};
use rand::{Rng}; 
use serde::{Serialize};
use ff::{Field, PrimeField};
use time::Timespec;
#[cfg(target_arch = "wasm32")]
use js_sys::Date;
#[cfg(not(target_arch = "wasm32"))]
extern crate time;

pub struct ThresholdDecryptor {
    private_key : PrivateKey
}

// Returns L_i(0) where L_i(x) is the unique polynomical such that L_i(i) = 1 and L_i(x) = 0 for all x other than i in range 0..n
pub fn lagrange_basis_at_0(i: u32, n:u32) -> Fr {
    assert!(i > 0, "i must be greater than 0");
    assert!(n > 0, "n must be greater than 0");
    let one = Fr::one();
    let mut acc = one.clone();
    let mut j: u32 = 1;
    let i_ = Fr::from_str(&i.to_string()).unwrap();
    // since we are evaluating L_i(x) where x=0, can set x to 0 in formula for lagrange basis. Formula becomes becomes product of j / (j-i) for all j not equal to i
    while j <= n {
        if j == i {
            println!("j and i are {} and {} ! continü", j, i);
            j+=1;
            continue;
        }
        println!("j is {}", j);
        let j_: Fr = Fr::from_str(&j.to_string()).unwrap();
        println!("j_ is {:?}", j_);
        // numerator = j, demoninator = j - i
        let mut denominator = j_.clone();
        denominator.sub_assign(&i_);
        
        println!("acc is {:?}", acc);
        acc.mul_assign(&j_);

        println!("denominator {:?}", denominator);
        println!("inverse {:?}", denominator.inverse().unwrap());
        acc.mul_assign(&denominator.inverse().unwrap());
        println!("acc is now {:?}", acc);
        j+=1;
    }

    acc
}

pub fn decrypt(encrypted: ElGamalEncryption, shares: Vec<Point>, num_shares_needed: u64) {
    assert!(shares.len().to_u64().unwrap() >= num_shares_needed);
}

impl ThresholdDecryptor {
    pub fn pubkey(&self) -> Point {
        self.private_key.public()
    }
    pub fn decryption_share(msg: &Point) {
        let m = msg.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_lagrange_basis_at_0() {
        // test for reconstructing y-intercept of line with points (1,5) and (2,6). test that y-intercept is 4
        let n: u32 = 2; // n  =  number of shares  =  degree of polynomial + 1
        let l1 = lagrange_basis_at_0(1 as u32, n);
        let l2 = lagrange_basis_at_0(2 as u32, n);

        println!("\n\nl1 l2\n\n{:?}\n{:?}\n\n", l1, l2);

        let y1 = Fr::from_str("5").unwrap();
        let y2 = Fr::from_str("6").unwrap();
        // calculate l1y1+l2y2

        // part 1
        let mut result = l1.clone();
        result.mul_assign(&y1);
        
        // part 2
        let mut part2 = l2.clone();
        part2.mul_assign(&y2);
        
        result.add_assign(&part2);

        assert!(result.eq(&Fr::from_str("4").unwrap()));



        // Now, try the same thing but for a degree-3 polynomial: 3x^2+100x+123. Points are (1, 226), (2, 335) and (3, 450)
        // test for reconstructing y-intercept of line with points (1,5) and (2,6). test that y-intercept is 4
        let n: u32 = 3; // n  =  number of shares  =  degree of polynomial + 1
        let l1 = lagrange_basis_at_0(1 as u32, n);
        let l2 = lagrange_basis_at_0(2 as u32, n);
        let l3 = lagrange_basis_at_0(3 as u32, n);

        println!("\n\nl1 l2 l3\n\n{:?}\n{:?}\n{:?}\n\n", l1, l2, l3);
        let y1 = Fr::from_str("226").unwrap();
        let y2 = Fr::from_str("335").unwrap();
        let y3 = Fr::from_str("450").unwrap();
        // calculate l1y1+l2y2

        // part 1
        let mut result = l1.clone();
        result.mul_assign(&y1);
        
        // part 2
        let mut part2 = l2.clone();
        part2.mul_assign(&y2);

        // part 3
        let mut part3 = l3.clone();
        part3.mul_assign(&y3);
        
        
        result.add_assign(&part2);
        result.add_assign(&part3);
        assert!(result.eq(&Fr::from_str("123").unwrap()));
        
    }
}