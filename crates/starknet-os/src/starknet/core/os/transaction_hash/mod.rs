use cairo_vm::Felt252;
use starknet_api::transaction::fields::ValidResourceBounds;

pub const L1_GAS: &str = "L1_GAS";
pub const L2_GAS: &str = "L2_GAS";

/// https://github.com/starkware-libs/cairo-lang/blob/8276ac35830148a397e1143389f23253c8b80e93/src/starkware/starknet/core/os/transaction_hash/transaction_hash.py#L180-L208
pub fn create_resource_bounds_list(resource_bounds: &ValidResourceBounds) -> Vec<Felt252> {
    let l1_gas = Felt252::from_bytes_be_slice(L1_GAS.as_bytes());
    let l2_gas = Felt252::from_bytes_be_slice(L2_GAS.as_bytes());
    let l1_data = Felt252::from_bytes_be_slice("L1_DATA".as_bytes());

    let mut resource_bounds_vec = Vec::new();

    let l1_bounds = resource_bounds.get_l1_bounds();
    let l2_bounds = resource_bounds.get_l2_bounds();

    match resource_bounds {
        ValidResourceBounds::L1Gas(_) => {
            // Only include L1 and L2 gas
            resource_bounds_vec.push(l1_gas);
            resource_bounds_vec.push(l1_bounds.max_amount.into());
            resource_bounds_vec.push(l1_bounds.max_price_per_unit.into());

            resource_bounds_vec.push(l2_gas);
            resource_bounds_vec.push(l2_bounds.max_amount.into());
            resource_bounds_vec.push(l2_bounds.max_price_per_unit.into());
        }

        ValidResourceBounds::AllResources(all_bounds) => {
            // Include all resources
            resource_bounds_vec.push(l1_gas);
            resource_bounds_vec.push(all_bounds.l1_gas.max_amount.into());
            resource_bounds_vec.push(all_bounds.l1_gas.max_price_per_unit.into());

            resource_bounds_vec.push(l2_gas);
            resource_bounds_vec.push(all_bounds.l2_gas.max_amount.into());
            resource_bounds_vec.push(all_bounds.l2_gas.max_price_per_unit.into());

            resource_bounds_vec.push(l1_data);
            resource_bounds_vec.push(all_bounds.l1_data_gas.max_amount.into());
            resource_bounds_vec.push(all_bounds.l1_data_gas.max_price_per_unit.into());
        }
    }

    resource_bounds_vec
}
