use num_bigint::{RandBigInt, BigInt, Sign};
use num_traits::{FromPrimitive};
use babyjubjub_rs::{Fl, SUBORDER};
use blake2::{Blake2b512, Digest};
use ff::{Field, PrimeField};
// use num_bigint::Sign;
use std::ops::Mul;
use serde::{Serialize, Deserialize};


// impl Serialize for Polynomial {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where
//             S: serde::Serializer {
//                 let mut seq = serializer.serialize_seq(Some(self.coefficients.len()))?;
//                 self.coefficients.iter().for_each(
//                     |coef|  { seq.serialize_element(&coef.to_string()); }
//                 );
//                 seq.end()
//             }
// }

#[derive(Serialize, Deserialize)]
pub struct Polynomial {
    coefficients: Vec<BigInt>
}

impl Polynomial {
    pub fn from_coeffs(coeffs: Vec<BigInt>) -> Polynomial {
        Polynomial { coefficients: coeffs }
    }

    // Creates a random polynomial with elements in Fl
    pub fn random_polynomial_fl(degree: usize) -> Polynomial {
        let coeffs = (0..degree+1).map(
            |_| rand::thread_rng().gen_bigint_range(&BigInt::from_u8(0u8).unwrap() , &SUBORDER)
        ).collect::<Vec<BigInt>>();

        Polynomial { coefficients: coeffs }
    }

    /// Genereates polynomial from a random seed by repeatedly hashing it to get eeach new coefficient
    pub fn from_seed(seed: &Vec<u8>, degree: usize) -> Polynomial {
        assert!(seed.len() == 32, "seed must be 32 bytes");
        let sub_order = SUBORDER.clone(); // Perhaps not most efficient way of doing it but it should be OK
        let mut coeffs: Vec<BigInt> = vec![];
        let mut recent: Vec<u8> = seed.clone();
        for _ in 0..degree+1 {
            let mut h = Blake2b512::new();
            h.update(recent);
            recent = h.finalize().to_vec();
            let as_bigint = BigInt::from_bytes_be(Sign::Plus, &recent);
            coeffs.push(as_bigint % &sub_order);
        }
        Polynomial::from_coeffs(coeffs)
    }

    pub fn eval(&self, x: &BigInt) -> BigInt{
        self.coefficients.iter().enumerate().map(
            |(i, coeff)| x.pow(i as u32).mul(coeff)
        ).sum::<BigInt>()
    }

    /// Degree of the polynomial
    pub fn deg(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// adds to another polynomial of same degree
    pub fn add_same_deg(&self, other_polynomial: &Polynomial) -> Polynomial {
        assert_eq!(self.deg(), other_polynomial.deg(), 
            "Error adding polynomials with coefficients {:?} and {:?} Currently, adding polynomials is only supported for polynomials of the same degree",
            self.coefficients, other_polynomial.coefficients
        );
        let new_coefs = self.coefficients.iter().zip(
            other_polynomial.coefficients.clone()
        ).map(
            |(a,b)| a + b
        ).collect();
        Polynomial { coefficients: new_coefs }
    }

}

// NOTE: look more into security of a user bieng able to ask "decrypt this with nodes i1, i2, and i3", then being able to asl "decrypt this with nodes i4, i5, and i6". Does this reveal any information about the private key? I would assume not because this is standard, but seems strange and still worth more detailed analysis.
// Returns L_i(0) where L_i(x) is the unique polynomical such that L_i(i) = 1 and L_i(x) = 0 for all x in set indices other than i
pub fn lagrange_basis_at_0(i: u32, indices: &Vec<u32>) -> Fl {
    assert!(i > 0, "i must be greater than 0");
    // assert!(n > 0, "n must be greater than 0");
    let one = Fl::one();
    let mut acc = one.clone();
    let i_ = Fl::from_str(&i.to_string()).unwrap();
    // since we are evaluating L_i(x) where x=0, can set x to 0 in formula for lagrange basis. Formula becomes becomes product of j / (j-i) for all j not equal to i
    // while j <= n {
    for j in indices.iter() {
        if *j != i {
            let j_: Fl = Fl::from_str(&j.to_string()).unwrap();
            // numerator = j, demoninator = j - i
            let mut denominator = j_.clone();
            denominator.sub_assign(&i_);
            
            acc.mul_assign(&j_);

            acc.mul_assign(&denominator.inverse().unwrap());
        }
    }
    acc
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use num_bigint::ToBigInt;
    use super::*;

    #[test]
    fn test_polynomial() {
        // polynomial is 123456789 + 69x + 987654321x^2
        let coefficients: Vec<BigInt> = [123456789.to_bigint(), 69.to_bigint(), 987654321.to_bigint()]
                                        .map(|x|x.unwrap())
                                        .to_vec();
        let polynomial = Polynomial::from_coeffs(coefficients);
        assert!(polynomial.eval(&0.to_bigint().unwrap()) == 123456789.to_bigint().unwrap());
        assert!(polynomial.eval(&123.to_bigint().unwrap()) == BigInt::from_str("14942345687685").unwrap());
    }

    #[test]
    fn test_random_polynomial_degree() {
        let p0 = Polynomial::random_polynomial_fl(0);
        let p1 = Polynomial::random_polynomial_fl(1);
        let p2 = Polynomial::random_polynomial_fl(2);
        let p3 = Polynomial::random_polynomial_fl(3);
        assert!(p0.coefficients.len() == 1);
        assert!(p1.coefficients.len() == 2);
        assert!(p2.coefficients.len() == 3);
        assert!(p3.coefficients.len() == 4);
    }

    #[test]
    fn test_lagrange_basis_at_0_2of2() {
        // TODO: refactor this to be more concise

        // test for reconstructing y-intercept of line with points (1,5) and (2,6). test that y-intercept is 4
        // let n: u32 = 2; // n  =  number of shares  =  degree of polynomial + 1
        let l1 = lagrange_basis_at_0(1 as u32, &vec![1,2]);
        let l2 = lagrange_basis_at_0(2 as u32, &vec![1,2]);

        let y1 = Fl::from_str("5").unwrap();
        let y2 = Fl::from_str("6").unwrap();
        // calculate l1y1+l2y2

        // part 1
        let mut result = l1.clone();
        result.mul_assign(&y1);
        
        // part 2
        let mut part2 = l2.clone();
        part2.mul_assign(&y2);
        
        result.add_assign(&part2);

        assert!(result.eq(&Fl::from_str("4").unwrap()));
    }

    // Now, try the same thing but for a degree-2 polynomial: 3x^2+100x+123. Points are (1, 226), (2, 335) and (3, 450)
    // Test that y-intercept is 123
    #[test]
    fn test_lagrange_basis_at_0_3of3() {
        let nodes_to_decrypt_from: Vec<u32> = vec![1,2,3];
        // Now, try the same thing but for a degree-2 polynomial (3/3 secret shared)
        let l1 = lagrange_basis_at_0(1 as u32, &nodes_to_decrypt_from);
        let l2 = lagrange_basis_at_0(2 as u32, &nodes_to_decrypt_from);
        let l3 = lagrange_basis_at_0(3 as u32, &nodes_to_decrypt_from);

        let y1 = Fl::from_str("226").unwrap();
        let y2 = Fl::from_str("335").unwrap();
        let y3 = Fl::from_str("450").unwrap();
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
        assert!(result.eq(&Fl::from_str("123").unwrap()));
        
    }

    // Now, try the same thing but for a degree-1 polynomial: 123x+321. Points are (1, 444), (2, 567) and (3, 690)
    // Test that y-intercept is 321 and can be reconstructed from nodes 1 and 2, nodes 2 and 3, and nodes 1 and 3
    #[test]
    fn test_lagrange_basis_at_0_2of3_successful_reconsrtruction_for_each_pair_of_2_nodes() {
        // Each of these pairs should be sufficient to reconstruct the shared secret
        // Pairs consist of node indices and their corresponding lagrange bases at 0
        let pairs: Vec<[(u32, Fl); 2]> = vec![
            [
                (1, lagrange_basis_at_0(1 as u32, &vec![1,2])),
                (2, lagrange_basis_at_0(2 as u32, &vec![1,2]))
            ],
            [
                (2, lagrange_basis_at_0(2 as u32, &vec![2,3])),
                (3, lagrange_basis_at_0(3 as u32, &vec![2,3]))
            ],
            [
                (1, lagrange_basis_at_0(1 as u32, &vec![1,3])),
                (3, lagrange_basis_at_0(3 as u32, &vec![1,3]))
            ]
        ];
        
        let y1 = Fl::from_str("444").unwrap();
        let y2 = Fl::from_str("567").unwrap();
        let y3 = Fl::from_str("690").unwrap();

        let secret_share = |x| {
            if x == 1 {
                y1
            } else if x == 2 {
                y2
            } else if x == 3 {
                y3
            }
            else {
                panic!("Invalid node index")
            }
        };

        pairs.iter().for_each(|pair|{
            let (idx0, lb0) = pair[0];
            let (idx1, lb1) = pair[1];
            
            // Add up the secret shares * lagrange bases at 0 for each pair. This should recosntruct the secret, which should be the same for each pair
            let mut result = lb0.clone();
            result.mul_assign(&secret_share(idx0));

            let mut part2 = lb1.clone();
            part2.mul_assign(&secret_share(idx1));

            result.add_assign(&part2);
            assert!(result.eq(&Fl::from_str("321").unwrap()));

        });
        
    }

    #[test]
    pub fn test_add_same_deg() {
        let p1 = Polynomial::from_coeffs(
            vec![
                100.to_bigint().unwrap(),
                69.to_bigint().unwrap(),
                0.to_bigint().unwrap(),
                7.to_bigint().unwrap(),
            ]
        );
        let p2 = Polynomial::from_coeffs(
            vec![
                9.to_bigint().unwrap(),
                1.to_bigint().unwrap(),
                5.to_bigint().unwrap(),
                0.to_bigint().unwrap(),
            ]
        );
        let p3 = p1.add_same_deg(&p2);
        assert!(
            (p3.coefficients[0] == 109.to_bigint().unwrap()) &&
            (p3.coefficients[1] == 70.to_bigint().unwrap()) &&
            (p3.coefficients[2] == 5.to_bigint().unwrap()) &&
            (p3.coefficients[3] == 7.to_bigint().unwrap())
        )
    }

}
