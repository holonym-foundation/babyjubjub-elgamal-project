// use ethers::{
//     core::types::Address,
//     providers::{Http, Provider},
// };
use ethers::contract::abigen;
use ethers::prelude::*;
use std::{sync::Arc, env};

#[tokio::main]
pub async fn has_access(c1x: u32) -> bool {
    let rpc_url = env::var("ZK_ESCROW_RPC_URL").expect("ZK_ESCROW_RPC_URL must be set");
    let provider = Provider::<Http>::try_from(rpc_url).unwrap();

    abigen!(SimpleAccessControl, r#"./SimpleAccessControl.json"#);
    let client = Arc::new(provider);
    let address = "0x3A3b5aEF636D2131dd7Ab8413f104c338E723357".parse::<Address>().unwrap();
    let the_sac = SimpleAccessControl::new(address, Arc::clone(&client));

    the_sac.has_access(c1x.into()).await.unwrap()

}