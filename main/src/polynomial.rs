use num_bigint::{RandBigInt, BigInt};
use num_traits::{FromPrimitive, ToPrimitive};
use babyjubjub_rs::{Fr, Point, ElGamalEncryption, B8, FrToBigInt};
use ff::{Field, PrimeField};
use std::ops::Mul;
use babyjubjub_rs::Q;
// enum PolynomialRepr {
//     Coefficients(Vec<BigInt>),
//     Points(Vec<(u32, BigInt)>) //x,y coordinates are represented as u32,bigint. This is weird but convenient since x is always small for these use cases
// }


pub struct Polynomial {
    coefficients: Vec<BigInt>
}

impl Polynomial {
    pub fn from_coeffs(coeffs: Vec<BigInt>) -> Polynomial {
        Polynomial { coefficients: coeffs }
    }

    // Creates a random polynomial with elements in Fr
    pub fn random_polynomial_fr(degree: u32) -> Polynomial {
        let coeffs = (0..degree).map(
            |_| rand::thread_rng().gen_bigint_range(&BigInt::from_u8(0u8).unwrap() , &Q)
        ).collect::<Vec<BigInt>>();

        Polynomial { coefficients: coeffs }
    }

    pub fn eval(&self, x: &BigInt) -> BigInt{
        self.coefficients.iter().enumerate().map(
            |(i, coeff)| x.pow(i as u32).mul(coeff)
        ).sum::<BigInt>()
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::Mul, str::FromStr};
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
    fn test_lagrange_basis_at_0() {
        // TODO: refactor this to be more concise

        // test for reconstructing y-intercept of line with points (1,5) and (2,6). test that y-intercept is 4
        let n: u32 = 2; // n  =  number of shares  =  degree of polynomial + 1
        let l1 = lagrange_basis_at_0(1 as u32, n);
        let l2 = lagrange_basis_at_0(2 as u32, n);

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

    #[test]
    fn test_keygen() {

    }
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
            j+=1;
            continue;
        }
        let j_: Fr = Fr::from_str(&j.to_string()).unwrap();
        // numerator = j, demoninator = j - i
        let mut denominator = j_.clone();
        denominator.sub_assign(&i_);
        
        acc.mul_assign(&j_);

        acc.mul_assign(&denominator.inverse().unwrap());

        j+=1;
    }

    acc
}
