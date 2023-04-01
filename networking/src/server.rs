/**
 * Simple HTTPS server. 
 * Run with `cargo run path/to/server.crt ./path/to/server.key`.
 */
use std::io;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls_pemfile::{certs, rsa_private_keys, pkcs8_private_keys};
use tokio;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use clap::{App, Arg};

fn read_cert_pem(file: &File) -> Vec<Certificate> {
    let mut pem_reader = io::BufReader::new(file);
    let cert_chain = certs(&mut pem_reader).unwrap();
    let cert_chain: Vec<Certificate> = cert_chain
        .iter()
        .map(|cert| Certificate(cert.clone()))
        .collect();
    cert_chain
}

fn read_key_file(file: &File) -> Vec<PrivateKey> {
    let mut keys_reader = io::BufReader::new(file);
    // TODO: Change if you are using RSA keys
    // let keys_as_u8_vec = rsa_private_keys(&mut keys_reader).unwrap();
    let keys_as_u8_vec = pkcs8_private_keys(&mut keys_reader).unwrap();
    let mut keys: Vec<PrivateKey> = keys_as_u8_vec
        .iter()
        .map(|key| PrivateKey(key.clone()))
        .collect();
    keys
}

async fn run_server(
    cert_chain: Vec<Certificate>,
    private_keys: Vec<PrivateKey>
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(cert_chain.len() > 0, "No certificates found");
    assert!(private_keys.len() > 0, "No private keys found");
    // Configure server
    let tls_cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_keys[0].clone())
        .unwrap();
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000)); // TODO: Make port an argument
    let listener = TcpListener::bind(&addr).await?;
    // Run server
    println!("Listening on: {}", addr);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let fut = async move {
            let mut stream = acceptor.accept(stream).await?;
            let mut output = tokio::io::sink();
            // TODO: Change response
            stream
                .write_all(
                    &b"HTTP/1.0 200 ok\r\n\
                    Connection: close\r\n\
                    Content-length: 12\r\n\
                    \r\n\
                    Hello world!"[..],
                )
                .await?;
            stream.shutdown().await?;
            tokio::io::copy(&mut stream, &mut output).await?;
            Ok(()) as io::Result<()>
        };
        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("")
        .version("0.0.0")
        // .author("")
        .about("Whatever it does")
        .arg(
            Arg::new("path_to_cert_pem")
                .help("Path to the certificate PEM file")
                .required(true)
                .value_name("PATH_TO_CERT_PEM")
                .index(1),
        )
        .arg(
            Arg::new("path_to_key_pem")
                .help("Path to the certificate PEM file")
                .value_name("PATH_TO_KEY_PEM")
                .required(true)
                .index(2),
        )
        .get_matches();

    let path_to_cert_pem = matches.value_of("path_to_cert_pem").unwrap();
    let path_to_key_pem = matches.value_of("path_to_key_pem").unwrap();

    let cert_file = File::open(path_to_cert_pem).expect("Failed to open cert file");
    let key_file = File::open(path_to_key_pem).expect("Failed to open key file");

    let cert_chain = read_cert_pem(&cert_file);
    let keys = read_key_file(&key_file);

    match run_server(cert_chain, keys).await {
          Ok(_) => (),
      Err(err) => eprintln!("{:?}", err),
    }
}
