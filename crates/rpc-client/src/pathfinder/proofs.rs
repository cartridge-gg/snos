use serde::Deserialize;
use starknet_os::config::DEFAULT_STORAGE_TREE_HEIGHT;
use starknet_os::crypto::pedersen::PedersenHash;
use starknet_os::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
use starknet_os::storage::dict_storage::DictStorage;
use starknet_os::storage::storage::{Fact, HashFunctionType};
use starknet_types_core::felt::Felt;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum TrieNode {
    #[serde(rename = "binary")]
    Binary { left: Felt, right: Felt },
    #[serde(rename = "edge")]
    Edge { child: Felt, path: EdgePath },
}

impl TrieNode {
    pub fn hash<H: HashFunctionType>(&self) -> Felt {
        match self {
            TrieNode::Binary { left, right } => {
                let fact = BinaryNodeFact::new((*left).into(), (*right).into())
                    .expect("storage proof endpoint gave us an invalid binary node");

                // TODO: the hash function should probably be split from the Fact trait.
                //       we use a placeholder for the Storage trait in the meantime.
                Felt::from(<BinaryNodeFact as Fact<DictStorage, H>>::hash(&fact))
            }
            TrieNode::Edge { child, path } => {
                let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))
                    .expect("storage proof endpoint gave us an invalid edge node");
                // TODO: the hash function should probably be split from the Fact trait.
                //       we use a placeholder for the Storage trait in the meantime.
                Felt::from(<EdgeNodeFact as Fact<DictStorage, H>>::hash(&fact))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContractData {
    /// Root of the Contract state tree
    pub root: Felt,
    /// The proofs associated with the queried storage values
    pub storage_proofs: Vec<Vec<TrieNode>>,
}

#[derive(thiserror::Error, Debug)]
pub enum ProofVerificationError<'a> {
    #[error("Non-inclusion proof for key {}. Height {}.", key.to_hex_string(), height.0)]
    NonExistenceProof { key: Felt, height: Height, proof: &'a [TrieNode] },

    #[error("Proof verification failed, node_hash {node_hash:x} != parent_hash {parent_hash:x}")]
    InvalidChildNodeHash { node_hash: Felt, parent_hash: Felt },

    #[error("Conversion error")]
    ConversionError,
}

impl ContractData {
    /// Verifies that each contract state proof is valid.
    pub fn verify(&self, storage_keys: &[Felt]) -> Result<(), Vec<ProofVerificationError>> {
        let mut errors = vec![];

        tracing::debug!("Verifying keys {:?} for proofs {:?}", storage_keys, self.storage_proofs);

        for (index, storage_key) in storage_keys.iter().enumerate() {
            tracing::debug!("Verifying key {:?}", storage_key);

            if let Err(e) = verify_proof::<PedersenHash>(*storage_key, self.root, &self.storage_proofs[index]) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            dbg!("OK");
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathfinderProof {
    pub state_commitment: Felt,
    pub class_commitment: Option<Felt>,
    pub contract_proof: Vec<TrieNode>,
    pub contract_data: Option<ContractData>,
}

#[allow(dead_code)]
#[derive(Clone, Deserialize, Debug)]
pub struct PathfinderClassProof {
    pub class_commitment: Felt,
    pub class_proof: Vec<TrieNode>,
}

impl PathfinderClassProof {
    /// Verifies that the class proof is valid.
    pub fn verify(&self, class_hash: Felt) -> Result<(), ProofVerificationError> {
        verify_proof::<PedersenHash>(class_hash, self.class_commitment, &self.class_proof)
    }
}

// Types defined for Deserialize functionality
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EdgePath {
    pub len: u64,
    pub value: Felt,
}

/// This function goes through the tree from top to bottom and verifies that
/// the hash of each node is equal to the corresponding hash in the parent node.
pub fn verify_proof<H: HashFunctionType>(
    key: Felt,
    commitment: Felt,
    proof: &[TrieNode],
) -> Result<(), ProofVerificationError> {
    // // Comment this to try verifying the proofs.
    // return Ok(());

    let bits = key.to_bits_be();

    let mut parent_hash = commitment;

    // The tree height is 251, so the first 5 bits are ignored.
    let start = 5;
    let mut index = start;

    for node in proof.iter() {
        let node_hash = node.hash::<H>();
        if node_hash != parent_hash {
            return Err(ProofVerificationError::InvalidChildNodeHash { node_hash, parent_hash });
        }

        match node {
            TrieNode::Binary { left, right } => {
                parent_hash = if bits[index as usize] { *right } else { *left };
                index += 1;
            }
            TrieNode::Edge { child, path } => {
                let path_len_usize: usize = path.len.try_into().map_err(|_| ProofVerificationError::ConversionError)?;
                let index_usize: usize = index.try_into().map_err(|_| ProofVerificationError::ConversionError)?;

                let path_bits = path.value.to_bits_be();
                let relevant_path_bits = &path_bits[path_bits.len() - path_len_usize..];
                let key_bits_slice = &bits[index_usize..(index_usize + path_len_usize)];

                parent_hash = *child;
                index += path.len;

                if relevant_path_bits != key_bits_slice {
                    // If paths don't match, we've found a proof of non-membership because:
                    // 1. We correctly moved towards the target as far as possible, and
                    // 2. Hashing all the nodes along the path results in the root hash, which means
                    // 3. The target definitely does not exist in this tree
                    return Err(ProofVerificationError::NonExistenceProof {
                        key,
                        height: Height(DEFAULT_STORAGE_TREE_HEIGHT - (index - start)),
                        proof,
                    });
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use katana_rpc_types::trie::GetStorageProofResponse;
    use serde_json::json;
    use starknet::macros::felt;

    use super::verify_proof;
    use crate::pathfinder::client::{katana_to_pathfinder_class_proof, katana_to_pathfinder_proof};

    #[test]
    fn try_and_test() {
        // this is a proof at block 0 for the default erc20 class
        let class = felt!("0xa2475bc66197c751d854ea8c39c6ad9781eb284103bcd856b58e6b500078ac");
        let json = json!(
                  {
          "global_roots": {
            "block_hash": "0x607578c124baf60f2746ee38c8eeae659a707865aa08b7fc8ad3615da8b7d27",
            "classes_tree_root": "0x293683b0969bf287d02cafc9d7f52769f1dd4b7e6441b9b7a319265d773fa7e",
            "contracts_tree_root": "0x6887d660c11fe4f16b3b81046c03fd270a4580d7b89e33fd035d324a256ffe0"
          },
          "classes_proof": {
            "nodes": [
              {
                "node_hash": "0x293683b0969bf287d02cafc9d7f52769f1dd4b7e6441b9b7a319265d773fa7e",
                "node": {
                  "left": "0x7d3f57cf7e6870b49a3fc8dca60c1757ceae8997bed2344d9ed269761536dfd",
                  "right": "0x684042b4d54c6a225b790fa72242729a51c37ec2d1bfbb2e4b1364a2b529d1f"
                }
              },
              {
                "node_hash": "0x7d3f57cf7e6870b49a3fc8dca60c1757ceae8997bed2344d9ed269761536dfd",
                "node": {
                  "left": "0x64b577ca42227b2a3f4e2d051e7676aa2ee06d9b16e156a43a520d742558870",
                  "right": "0x2a8601edec0a0be626d1f612974cbbbf0c2beae0bd3ff3a2b8dddc63e53f174"
                }
              },
              {
                "node_hash": "0x64b577ca42227b2a3f4e2d051e7676aa2ee06d9b16e156a43a520d742558870",
                "node": {
                  "path": "0xa2475bc66197c751d854ea8c39c6ad9781eb284103bcd856b58e6b500078ac",
                  "length": 249,
                  "child": "0x525b9a35bfc86f1c3ed1e81b319e093a342b78cd7670bde235e3b80c18a231f"
                }
              }
            ]
          },
          "contracts_proof": {
            "nodes": [],
            "contract_leaves_data": []
          },
          "contracts_storage_proofs": {
            "nodes": []
          }
        });

        let katana_ty = serde_json::from_value::<GetStorageProofResponse>(json).unwrap();
        let pathfinder_proof = katana_to_pathfinder_class_proof(katana_ty);

        pathfinder_proof.verify(class).expect("failed to verify");
    }

    #[test]
    fn try_and_test2() {
        // values taken from katana's classes_proof test of the 2nd declared class
        let class = felt!("0x6db966e881855412564e8374de3d75a54b734128342e91d1e97d953706ccb42");
        let json = json!({
          "global_roots": {
            "block_hash": "0x7db24109bdc5525ffb957568a3a323e2543c16d4dfd7e50cd46ab3b681c8f8",
            "classes_tree_root": "0x65120756fb6a322809b37778a3c2dc249c498155b2c8119e5d76e7cb59ac65a",
            "contracts_tree_root": "0x562adc9d06ba19f7ef87533074c293cb4766ec767cac0595cb5bf3fee1085"
          },
          "classes_proof": {
            "nodes": [
              {
                "node_hash": "0x65120756fb6a322809b37778a3c2dc249c498155b2c8119e5d76e7cb59ac65a",
                "node": {
                  "left": "0xf70ffe9476fd6c13cbc6658445d0c6ddc5e2fc13caf808543d83f52de8cdfd",
                  "right": "0x4159e5b6ac758e155d0d4cfc28734d7bf5e05f7a3e8c7f2957a889d0510a07d"
                }
              },
              {
                "node_hash": "0x4159e5b6ac758e155d0d4cfc28734d7bf5e05f7a3e8c7f2957a889d0510a07d",
                "node": {
                  "path": "0x1",
                  "length": 1,
                  "child": "0x1f7fcbaf1d6d349b8288244bb59808471af1d30689c1d6cfb7ca0147e11734"
                }
              },
              {
                "node_hash": "0x1f7fcbaf1d6d349b8288244bb59808471af1d30689c1d6cfb7ca0147e11734",
                "node": {
                  "left": "0x287272f8aadd10860194a72408d766caef5fe06a8f4d4bcc9183adbf190b767",
                  "right": "0x15fec0b75c3699d5391db29cce825c48f2e45df821e285e61a10bca2d9e233b"
                }
              },
              {
                "node_hash": "0x287272f8aadd10860194a72408d766caef5fe06a8f4d4bcc9183adbf190b767",
                "node": {
                  "path": "0xdb966e881855412564e8374de3d75a54b734128342e91d1e97d953706ccb42",
                  "length": 248,
                  "child": "0x497d06b0fdffe2b6b80182d50107f51ca9a557914a6ea0daa7e7c77c93b113e"
                }
              }
            ]
          },
          "contracts_proof": {
            "nodes": [],
            "contract_leaves_data": []
          },
          "contracts_storage_proofs": {
            "nodes": []
          }
        });

        let katana_ty = serde_json::from_value::<GetStorageProofResponse>(json).unwrap();
        let pathfinder_proof = katana_to_pathfinder_class_proof(katana_ty);

        pathfinder_proof.verify(class).expect("failed to verify");
    }

    #[test]
    fn storage_proof() {
        let address = felt!("0x1f401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d");
        let storage_key = felt!("0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f");

        let json = json!({
          "global_roots": {
            "block_hash": "0x607578c124baf60f2746ee38c8eeae659a707865aa08b7fc8ad3615da8b7d27",
            "classes_tree_root": "0x64de0d67f4afca0889f86042a1ceffd1835694eece8b94882c3a1f76e76beac",
            "contracts_tree_root": "0x66fdff8b024e8e177397362bbb85b7d590561daf74cc78bd026e495ad7f65b8"
          },
          "classes_proof": {
            "nodes": []
          },
          "contracts_proof": {
            "nodes": [
              {
                "node_hash": "0x66fdff8b024e8e177397362bbb85b7d590561daf74cc78bd026e495ad7f65b8",
                "node": {
                  "left": "0x3af57825237ee80adad2acdd2b2c868af79f561dcfca653d194ea02042c3240",
                  "right": "0x18c1253d675f20733ab9da1e815758cf660b1a7ea93e035eed508df3aeec98c"
                }
              },
              {
                "node_hash": "0x3af57825237ee80adad2acdd2b2c868af79f561dcfca653d194ea02042c3240",
                "node": {
                  "left": "0x2e05297cb4ba5b548fa7312948e8a5547edbf5016a10fa293dedb3fa2d18534",
                  "right": "0x7aec3a4287c106f65b0f4b1bed2e44a95f8155af3ba031ab1f2c901719ffa45"
                }
              },
              {
                "node_hash": "0x2e05297cb4ba5b548fa7312948e8a5547edbf5016a10fa293dedb3fa2d18534",
                "node": {
                  "path": "0x1",
                  "length": 1,
                  "child": "0x69881d08e90ac3b322164f6be03f3db125a732f8696e7a2fa3c77053cc656da"
                }
              },
              {
                "node_hash": "0x69881d08e90ac3b322164f6be03f3db125a732f8696e7a2fa3c77053cc656da",
                "node": {
                  "left": "0x1047636f59a5eac93c4aeda2f53708e59f101e2866f0ccb8252f78089f6d11d",
                  "right": "0x771820c189bc2f5bc70c38b55af6de985dc79ecda72998301dcf8d8908e58b0"
                }
              },
              {
                "node_hash": "0x771820c189bc2f5bc70c38b55af6de985dc79ecda72998301dcf8d8908e58b0",
                "node": {
                  "path": "0x7401c745d3dba9b9da11921d1fb006c96f571e9039a0ece3f3b0dc14f04c3d",
                  "length": 247,
                  "child": "0x113158def2a70808cb0b9df6b77fbe43a66b83dac588bab3eb4df7ab946b6d"
                }
              }
            ],
            "contract_leaves_data": [
              {
                "storage_root": "0x47de68226066999185a8a4299215bfedf45a20ce544bc298438917fc16949a4",
                "nonce": "0x0",
                "class_hash": "0x7dc7899aa655b0aae51eadff6d801a58e97dd99cf4666ee59e704249e51adf2"
              }
            ]
          },
          "contracts_storage_proofs": {
            "nodes": [
              [
                {
                  "node_hash": "0x47de68226066999185a8a4299215bfedf45a20ce544bc298438917fc16949a4",
                  "node": {
                    "path": "0x1379ac0624b939ceb9dede92211d7db5ee174fe28be72245b0a1a2abd81c98f",
                    "length": 251,
                    "child": "0x78e6e3e4a50285be0f6e8d0b8a61044033e24023df6eb95979ae4073f159ae6"
                  }
                }
              ]
            ]
          }
        });

        let katana_ty = serde_json::from_value::<GetStorageProofResponse>(json).unwrap();
        let pathfinder_proof = katana_to_pathfinder_proof(katana_ty);

        pathfinder_proof.contract_data.unwrap().verify(&[storage_key]).expect("must be able to verify");
    }
}
