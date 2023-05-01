// use ethers::{
//     core::types::Address,
//     providers::{Http, Provider},
// };
use ethers::contract::abigen;
use ethers::prelude::*;
use std::{sync::Arc};

// abigen!(IUniswapV2Pair, "./SimpleAccessControl.json");
const RPC_URL: &str = "https://eth.llamarpc.com";
const CONTRACT_PATH: &str = "../../../smart-contract-projects/access-control/src/AccessControl.sol";
#[tokio::main]
pub async fn has_access() {
    // let contract = Solc::default().compile_source(CONTRACT_PATH).unwrap();
    // println!("read {}", read_to_string(CONTRACT_PATH).unwrap());
    // let abi = contract.get(CONTRACT_PATH, "SimpleAccessControl").unwrap();//.abi.unwrap();
    // println!("abi: {:?}", abi);
    let provider = Provider::<Http>::try_from(RPC_URL).unwrap();
    // let block_number: U64 = provider.get_block_number().await.unwrap();
    // println!("{block_number}");
    abigen!(SimpleAccessControl, r#"./SimpleAccessControl.json"#);
    // abigen!(
    //     IERC20,
    //     r#"[
    //         function totalSupply() external view returns (uint256)
    //         function balanceOf(address account) external view returns (uint256)
    //         function transfer(address recipient, uint256 amount) external returns (bool)
    //         function allowance(address owner, address spender) external view returns (uint256)
    //         function approve(address spender, uint256 amount) external returns (bool)
    //         function transferFrom( address sender, address recipient, uint256 amount) external returns (bool)
    //         event Transfer(address indexed from, address indexed to, uint256 value)
    //         event Approval(address indexed owner, address indexed spender, uint256 value)
    //     ]"#,
    // );
    let client = Provider::<Http>::try_from("https://eth.llamarpc.com").unwrap();
    let client = Arc::new(client);
    // SimpleAccessControl address: 0x3A3b5aEF636D2131dd7Ab8413f104c338E723357
    // let address = "0x3A3b5aEF636D2131dd7Ab8413f104c338E723357".parse::<Address>().unwrap();
    
    
    
    // let pair = IUniswapV2Pair::new(address, Arc::clone(&client));

    // // getReserves -> get_reserves
    // let (reserve0, reserve1, _timestamp) = pair.get_reserves().call().await.unwrap();
    // println!("Reserves (ETH, USDT): ({reserve0}, {reserve1})");
}