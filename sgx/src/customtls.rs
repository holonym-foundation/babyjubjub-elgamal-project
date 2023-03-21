extern crate chrono;
extern crate mbedtls;

use chrono::prelude::*;

use mbedtls::hash::Type::Sha256;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::certificate::{Builder, Certificate};
use mbedtls::x509::Time;
use mbedtls::Result as TlsResult;
use mbedtls::alloc::Box;
use std::env;
use std::io::Read;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

const RSA_KEY_SIZE: u32 = 3072;
const RSA_KEY_EXP: u32 = 0x10001;
const DAYS_TO_SES: u64 = 86400;
const CERT_VAL_SECS: u64 = (365 * DAYS_TO_SES);

trait ToTime {
    fn to_time(&self) -> Time;
}

impl ToTime for chrono::DateTime<Utc> {
    fn to_time(&self) -> Time {
        Time::new(
            self.year() as _,
            self.month() as _,
            self.day() as _,
            self.hour() as _,
            self.minute() as _,
            self.second() as _,
        )
        .unwrap()
    }
}

fn get_validity() -> (Time, Time) {
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let end = start + CERT_VAL_SECS;
    let not_before = Utc.timestamp(start as _, 0);
    let not_after = Utc.timestamp(end as _, 0);
    (not_before.to_time(), not_after.to_time())
}

/// The below generates a key and a self signed certificate
/// to configure the TLS context.
/// SGX applications should not rely on untrusted sources for their key.
/// Ideally, enclaves communicating via TLS should, ideally,
/// also verify attestation information.
/// along with traditional certificate verification.
/// But this example doesn't show that.
fn get_key_and_cert() -> (Pk, Box<Certificate>) {
    let mut rng = Rdrand;
    let mut key = Pk::generate_rsa(&mut rng, RSA_KEY_SIZE, RSA_KEY_EXP).unwrap();
    let mut key_i = Pk::generate_rsa(&mut rng, RSA_KEY_SIZE, RSA_KEY_EXP).unwrap();
    let (not_before, not_after) = get_validity();

    let cert = Certificate::from_der(
        &Builder::new()
            .subject_key(&mut key)
            .subject_with_nul("CN=mbedtls-server.example\0")
            .unwrap()
            .issuer_key(&mut key_i)
            .issuer_with_nul("CN=mbedtls-server.example\0")
            .unwrap()
            .validity(not_before, not_after)
            .unwrap()
            .serial(&[5])
            .unwrap()
            .signature_hash(Sha256)
            .write_der_vec(&mut rng)
            .unwrap(),
    )
    .unwrap();
    (key, cert)
}

pub fn https_get() -> String {
    // let mut stream = TcpStream::connect("google.com:443")
    // .expect("Couldn't connect to the server...");
    // // stream.set_nonblocking(true).expect("set_nonblocking call failed");
    // let mut buf = vec![];
    
    // loop {
    //     println!("iterating");
    //     let res = stream.read_to_end(&mut buf);
    //     println!("res {:?}", res);
    //     match res {
    //         Ok(_) => break,
    //         // Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
    //         //     // wait until network socket is ready, typically implemented
    //         //     // via platform-specific APIs such as epoll or IOCP
    //         //     // wait_for_fd();
    //         // }
    //         Err(e) => panic!("encountered IO error: {}", e),
    //     };
    // };
    // println!("GOT bytes: {:?}", buf);

    // let entropy = Arc::new(entropy_new());
    // let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    // let (key, cert) = get_key_and_cert();
    // let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    env::set_var("RUST_BACKTRACE", "1");
    // let response = minreq::get("http://info.cern.ch:80")
    // // .with_header("Accept", "text/plain")
    // // .with_header("X-Best-Mon", "Sylveon")
    // .send()
    // .unwrap();
    // let body_str = response.as_str().unwrap();
    // body_str.to_string()
    minreq::get("http://127.0.0.1:3000").send().unwrap().as_str().unwrap().to_string()

}