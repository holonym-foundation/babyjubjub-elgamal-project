// Lambda server
#[macro_use]
extern crate lambda_runtime as lambda;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate simple_logger;

use babyjubjub_rs::{Point, Fr, ToDecimalString, B8};
use ff::PrimeField;
use lambda::error::HandlerError;
use num_bigint::BigInt;

use std::{error::Error, env};

#[derive(Deserialize, Clone)]
struct EventMaskedPoint {
    // #[serde(rename = "x")]
    x: String,
    y: String
}

#[derive(Serialize, Clone)]
struct CustomOutput {
    message: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(my_handler);

    Ok(())
}

fn my_handler(e: EventMaskedPoint, c: lambda::Context) -> Result<CustomOutput, HandlerError> {
    // if e.first_name == "" {
    //     error!("Empty first name in request {}", c.aws_request_id);
    //     return Err(c.new_error("Empty first name"));
    // }
    let p = Point {
        x: Fr::from_str(&e.x).unwrap(),
        y: Fr::from_str(&e.y).unwrap()
    };

    // Check it is safe to proceed, i.e. point is on the curve and in subgroup
    assert!(p.on_curve(), "Not on curve");
    // Note: in_subgroup just checks that order of the point is the order of the subgroup
    assert!(p.in_subgroup(), "Not in subgroup");

    // Get the private key env var
    let privkey = env::var("OPRF_KEY")
        .unwrap()
        .parse::<BigInt>()
        .unwrap();
    
    let result = p.mul_scalar(&privkey);

    Ok(CustomOutput {
        message: serde_json::to_string(&result).unwrap()//format!("{:?}, {:?}", result.x.to_dec_string(), result.y.to_dec_string()),
    })

}

#[cfg(test)]
mod tests {
    fn test_bad_point_fails() {
        // A good point: 69 * base point { x: Fr(0x2386db4e9cece81876fcb70ce852abdd6485f3299d63c2883dcc757ea9d7dbca), y: Fr(0x17f6e5fe9cfe68a74be26b435a55ac434bfa15475fdf1cae2eceb117c44af9cc) }
        todo!();
    }
}