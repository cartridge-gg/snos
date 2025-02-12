use cairo_vm::types::layout_name::LayoutName;
use prove_block::prove_block;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider, Url};

const DEFAULT_COMPILED_OS: &[u8] = include_bytes!("../../../../build/os_latest.json");

#[tokio::test(flavor = "multi_thread")]
async fn katana_prove_blocks() {
    const RPC_URL: &str = "http://localhost:5050";
    let client = JsonRpcClient::new(HttpTransport::new(Url::parse(RPC_URL).unwrap()));

    let latest_block = client.block_number().await.expect("Failed to get latest block number");
    println!("Proving blocks from 0 to {latest_block}");

    for block in 0..latest_block {
        println!("Processing block {block}");
        prove_block(DEFAULT_COMPILED_OS, block, RPC_URL, LayoutName::all_cairo, true)
            .await
            .expect("failed to run `prove_block` for block {i}");
    }
}
