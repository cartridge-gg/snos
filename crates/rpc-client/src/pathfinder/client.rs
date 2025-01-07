use std::collections::VecDeque;

use katana_rpc_types::trie::{GetStorageProofResponse, MerkleNode, NodeWithHash};
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use starknet::macros::{felt, short_string};
use starknet_types_core::felt::Felt;

use super::proofs::EdgePath;
use crate::pathfinder::proofs::{ContractData, PathfinderClassProof, PathfinderProof, TrieNode};

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
        let mut proofs = VecDeque::new();

        if keys.is_empty() {
            let proof = self.get_proof_one_key(block_number, contract_address, None).await?;
            proofs.push_back(proof);
        } else {
            for key in keys {
                let proof = self.get_proof_one_key(block_number, contract_address, Some(*key)).await?;
                proofs.push_back(proof);
            }
        }

        let mut the_ultimate_proof = proofs.pop_front().expect("must have at least one");
        let the_utimate_contract_data = the_ultimate_proof.contract_data.as_mut().expect("must have bruh");

        for proof in proofs {
            the_utimate_contract_data.storage_proofs.push(proof.contract_data.unwrap().storage_proofs[0].clone());
        }

        // let mut storage_proofs = vec![];
        // for p in proofs.iter() {
        //     if let Some(data) = p.contract_data.as_ref() {
        //         storage_proofs.push(data.storage_proofs[0].clone());
        //     }
        // }

        // let mut p0 = proofs[0].clone();
        // if let Some(data) = p0.contract_data.as_mut() {
        //     data.storage_proofs = storage_proofs;
        // }

        // dbg!(&p0);

        Ok(the_ultimate_proof)
    }

    async fn get_proof_one_key(
        &self,
        block_number: u64,
        contract_address: Felt,
        key: Option<Felt>,
    ) -> Result<PathfinderProof, ClientError> {
        let key = if let Some(key) = key { vec![key] } else { vec![] };

        let json = json!({
            "block_id": { "block_number": block_number },
            "contract_addresses": [contract_address],
            "contracts_storage_keys": [{
                "contract_address": contract_address,
                "storage_keys": key
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

// - this conversion function assumes that the proof is associated with only a single contract's storage key
// - everytime we fetch a storage proof, we should also request the contract proof.
pub(crate) fn katana_to_pathfinder_proof(proof: GetStorageProofResponse) -> PathfinderProof {
    let contract_proof = proof.contracts_proof;
    let contract_leaf = contract_proof.contract_leaves_data.first().expect("must have exactly one");
    let storage_proofs = proof.contracts_storage_proofs.nodes.first().expect("must have exactly one");

    let state_commitment = starknet_crypto::poseidon_hash_many(&[
        short_string!("STARKNET_STATE_V0"),
        proof.global_roots.contracts_tree_root,
        proof.global_roots.classes_tree_root,
    ]);

    // convert storage proofs to pathfinder types
    let mut pf_storage_proofs = Vec::with_capacity(1);
    let mut pf_storage_proof: Vec<TrieNode> = Vec::with_capacity(pf_storage_proofs.len());

    for n in &storage_proofs.0 {
        let NodeWithHash { node, .. } = n;
        pf_storage_proof.push(node.clone().into());
    }

    pf_storage_proofs.push(pf_storage_proof);

    // convert contract proofs to pathfinder types
    let mut pf_contract_proof: Vec<TrieNode> = Vec::with_capacity(contract_proof.nodes.len());
    for n in &contract_proof.nodes.0 {
        let NodeWithHash { node, .. } = n;
        pf_contract_proof.push(node.clone().into());
    }

    PathfinderProof {
        state_commitment,
        class_commitment: Some(proof.global_roots.classes_tree_root),
        contract_proof: pf_contract_proof,
        contract_data: Some(ContractData { root: contract_leaf.storage_root, storage_proofs: pf_storage_proofs }),
    }
}

pub(crate) fn katana_to_pathfinder_class_proof(proof: GetStorageProofResponse) -> PathfinderClassProof {
    PathfinderClassProof {
        class_commitment: proof.global_roots.classes_tree_root,
        class_proof: proof
            .classes_proof
            .nodes
            .iter()
            .map(|node| match node.node {
                MerkleNode::Binary { left, right } => TrieNode::Binary { left, right },
                MerkleNode::Edge { path, length, child } => {
                    TrieNode::Edge { child, path: EdgePath { len: length as u64, value: path } }
                }
            })
            .collect(),
    }
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
