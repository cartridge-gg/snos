use cairo_vm::Felt252;
use starknet_api::transaction::fields::ValidResourceBounds;

pub const L1_GAS: &str = "L1_GAS";
pub const L2_GAS: &str = "L2_GAS";

pub fn create_resource_bounds_list(resource_bounds: &ValidResourceBounds) -> Vec<Felt252> {
    let mut resource_bounds_vec = Vec::new();

    let l1_gas_name = Felt252::from_bytes_be_slice(L1_GAS.as_bytes());
    let l1_resource_bounds = resource_bounds.get_l1_bounds();
    resource_bounds_vec.push(l1_gas_name);
    resource_bounds_vec.push(l1_resource_bounds.max_amount.into());
    resource_bounds_vec.push(l1_resource_bounds.max_price_per_unit.into());

    let l2_gas_name = Felt252::from_bytes_be_slice(L2_GAS.as_bytes());
    let l2_resource_bounds = resource_bounds.get_l2_bounds();
    resource_bounds_vec.push(l2_gas_name);
    resource_bounds_vec.push(l2_resource_bounds.max_amount.into());
    resource_bounds_vec.push(l2_resource_bounds.max_price_per_unit.into());

    resource_bounds_vec
}
