use starknet_crypto::{pedersen_hash, Felt};
use starknet_os_types::hash::Hash;

use crate::storage::storage::HashFunctionType;

#[derive(Clone, Debug, PartialEq)]
pub struct PedersenHash;

impl HashFunctionType for PedersenHash {
    fn hash(x: &[u8], y: &[u8]) -> Hash {
        let x_felt = Felt::from_bytes_be_slice(x);
        let y_felt = Felt::from_bytes_be_slice(y);

        Hash::from_bytes_be(pedersen_hash(&x_felt, &y_felt).to_bytes_be())
    }
}
