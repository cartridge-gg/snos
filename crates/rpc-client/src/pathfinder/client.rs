use katana_rpc_types::trie::{GetStorageProofResponse, MerkleNode};
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet::macros::felt;
use starknet_types_core::felt::Felt;

use crate::pathfinder::proofs::{PathfinderClassProof, PathfinderProof, TrieNode};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Encountered a request error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Encountered a custom error: {0}")]
    CustomError(String),
}

fn jsonrpc_request(method: &str, params: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
        "params": params,
    })
}

async fn post_jsonrpc_request<T: DeserializeOwned>(
    client: &reqwest::Client,
    rpc_provider: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<T, ClientError> {
    let request = jsonrpc_request(method, params);
    let response = client.post(format!("{}", rpc_provider)).json(&request).send().await?;

    #[derive(Deserialize)]
    struct TransactionReceiptResponse<T> {
        result: T,
    }

    let response: TransactionReceiptResponse<T> = handle_error(response).await?;

    Ok(response.result)
}

async fn handle_error<T: DeserializeOwned>(response: Response) -> Result<T, ClientError> {
    match response.status() {
        StatusCode::OK => Ok(response.json().await?),
        s => {
            let error = response.text().await?;
            Err(ClientError::CustomError(format!("Received response: {s:?} Error: {error}")))
        }
    }
}

pub struct PathfinderRpcClient {
    /// A raw client to access endpoints not covered by starknet-rs.
    http_client: reqwest::Client,
    /// The base URL of the RPC client
    rpc_base_url: String,
}

impl PathfinderRpcClient {
    pub fn new(base_url: &str) -> Self {
        let starknet_rpc_url = format!("{}", base_url);
        tracing::info!("Starknet RPC URL: {}", starknet_rpc_url);
        let http_client =
            reqwest::ClientBuilder::new().build().unwrap_or_else(|e| panic!("Could not build reqwest client: {e}"));

        Self { http_client, rpc_base_url: base_url.to_string() }
    }

    pub async fn get_proof(
        &self,
        block_number: u64,
        contract_address: Felt,
        keys: &[Felt],
    ) -> Result<PathfinderProof, ClientError> {
        let mut proofs = vec![];
        for key in keys {
            proofs.push(self.get_proof_one_key(block_number, contract_address, *key).await?);
        }

        // dbg!(&proofs);

        let mut storage_proofs = vec![];
        for p in proofs.iter() {
            if let Some(data) = p.contract_data.as_ref() {
                storage_proofs.push(data.storage_proofs[0].clone());
            }
        }

        let mut p0 = proofs[0].clone();
        if let Some(data) = p0.contract_data.as_mut() {
            data.storage_proofs = storage_proofs;
        }

        // dbg!(&p0);

        Ok(p0)
    }

    async fn get_proof_one_key(
        &self,
        block_number: u64,
        contract_address: Felt,
        key: Felt,
    ) -> Result<PathfinderProof, ClientError> {
        let json = json!({
            "block_id": { "block_number": block_number },
            "contract_addresses": [contract_address],
            "contracts_storage_keys": [{
                "contract_address": contract_address,
                "storage_keys": [key]
            }]
        });

        log::debug!(
            "querying starknet_getProofs for address {:x} key {:?} at block {:x}:\n {}",
            contract_address,
            key,
            block_number,
            json
        );
        let r: Result<GetStorageProofResponse, ClientError> =
            post_jsonrpc_request(&self.http_client, &self.rpc_base_url, "starknet_getStorageProof", json).await;

        // dbg!("KATANA", &r);

        Ok(katana_to_pathfinder_proof(r?))
    }

    pub async fn get_class_proof(
        &self,
        block_number: u64,
        class_hash: &Felt,
    ) -> Result<PathfinderClassProof, ClientError> {
        log::debug!("querying starknet_getStorageProofs for class {:x} at block {:x}", class_hash, block_number);
        let r = post_jsonrpc_request(
            &self.http_client,
            &self.rpc_base_url,
            "starknet_getStorageProof",
            json!({ "block_id": { "block_number": block_number }, "class_hashes": [class_hash] }),
        )
        .await;
        log::debug!("response: {:?}", r);

        Ok(katana_to_pathfinder_class_proof(r?))
    }
}

const STARKNET_STATE_V0: Felt = felt!("0x535441524b4e45545f53544154455f5630");

fn katana_to_pathfinder_proof(proof: GetStorageProofResponse) -> PathfinderProof {
    let state_commitment = starknet_crypto::poseidon_hash_many(&[
        STARKNET_STATE_V0,
        proof.global_roots.contracts_tree_root,
        proof.global_roots.classes_tree_root,
    ]);

    // dbg!(&proof.contracts_proof.nodes);

    let storage_root = if proof.contracts_storage_proofs.nodes.is_empty() || proof.contracts_storage_proofs.nodes[0].0.is_empty() {
        Felt::ZERO
    } else {
        proof.contracts_storage_proofs.nodes[0].0[0].node_hash
    };

    // dbg!(&storage_root);

    // Build the storage proofs to have one array for each key.
    let mut storage_proofs: Vec<Vec<TrieNode>> = vec![];
    for n in proof.contracts_storage_proofs.nodes {
        let mut node_proofs = vec![];
        for nh in n.0.iter() {
            node_proofs.push(nh.node.into());
        }
        storage_proofs.push(node_proofs);
    }

    if storage_proofs.is_empty() {
        storage_proofs.push(vec![]);
    }

    // dbg!(&storage_proofs);

    // Compute the contract state root.
    let class_hash = proof.contracts_proof.contract_leaves_data[0].class_hash;
    let nonce = proof.contracts_proof.contract_leaves_data[0].nonce;
    // let storage_root = proof.contracts_proof.nodes[0].0[0].node_hash;

    //dbg!(&proof.contracts_proof.nodes[0].node_hash);

    let contract_trie_root = starknet_crypto::pedersen_hash(&class_hash, &storage_root);
    let contract_state_root = starknet_crypto::pedersen_hash(&contract_trie_root, &nonce);
    let contract_state_root = starknet_crypto::pedersen_hash(&contract_state_root, &Felt::ZERO);

    // dbg!(&contract_state_root);
    // dbg!(&proof.global_roots.contracts_tree_root);

    let p = PathfinderProof {
        state_commitment,
        class_commitment: Some(proof.global_roots.classes_tree_root),
        contract_proof: proof.contracts_proof.nodes.iter().map(|n| {dbg!(&n); n.node.into()}).collect(),
        contract_data: if storage_root == Felt::ZERO {
            None
        } else {
            Some(super::proofs::ContractData {
                root: contract_state_root,
                storage_proofs,
            })
        },
    };

    // dbg!(&p);

    p
}

fn katana_to_pathfinder_class_proof(_proof: GetStorageProofResponse) -> PathfinderClassProof {
    let p = PathfinderClassProof { class_commitment: Felt::ZERO, class_proof: vec![] };

    p
}

impl From<MerkleNode> for super::proofs::TrieNode {
    fn from(node: MerkleNode) -> Self {
        match node {
            MerkleNode::Edge { path, length, child } => super::proofs::TrieNode::Edge {
                path: super::proofs::EdgePath { value: path, len: length as u64 },
                child,
            },
            MerkleNode::Binary { left, right } => super::proofs::TrieNode::Binary { left, right },
        }
    }
}
