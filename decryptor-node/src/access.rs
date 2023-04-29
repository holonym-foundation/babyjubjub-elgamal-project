use ethers::{
    contract::abigen,
    core::types::Address,
    providers::{Http, Provider},
};
use std::sync::Arc;

abigen!(
    IUniswapV2Pair,
    r#"[
        function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
    ]"#,
);

#[tokio::main]
fn has_access() {
    let client = Provider::<Http>::try_from("https://eth.llamarpc.com").unwrap();
    let client = Arc::new(client);
    let address = "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852".parse::<Address>().unwrap();
    let pair = IUniswapV2Pair::new(address, Arc::clone(&client));

    // getReserves -> get_reserves
    let (reserve0, reserve1, _timestamp) = pair.get_reserves().call().await.unwrap();
    println!("Reserves (ETH, USDT): ({reserve0}, {reserve1})");
}