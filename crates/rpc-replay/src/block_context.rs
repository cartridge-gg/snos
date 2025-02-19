use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::versioned_constants::VersionedConstants;
use starknet::core::types::{BlockWithTxs, Felt, L1DataAvailabilityMode};
use starknet_api::block::{
    BlockInfo, BlockNumber, BlockTimestamp, GasPrice, GasPriceVector, GasPrices, NonzeroGasPrice, StarknetVersion,
};
use starknet_api::contract_address;
use starknet_api::core::ChainId;

use crate::utils::{felt_to_u128, FeltConversionError};

fn felt_to_gas_price(price: &Felt) -> Result<NonzeroGasPrice, FeltConversionError> {
    if *price == Felt::ZERO {
        return Err(FeltConversionError::CustomError("Gas price cannot be zero".to_string()));
    }

    let gas_price = felt_to_u128(price)?;
    NonzeroGasPrice::new(GasPrice(gas_price)).map_err(|e| FeltConversionError::CustomError(e.to_string()))
}

pub fn build_block_context(
    chain_id: ChainId,
    block: &BlockWithTxs,
    _: StarknetVersion,
) -> Result<BlockContext, FeltConversionError> {
    let sequencer_address_hex = block.sequencer_address.to_hex_string();
    let sequencer_address = contract_address!(sequencer_address_hex.as_str());
    let use_kzg_da = match block.l1_da_mode {
        L1DataAvailabilityMode::Blob => true,
        L1DataAvailabilityMode::Calldata => false,
    };

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices {
            eth_gas_prices: GasPriceVector {
                l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_wei)?,
                l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_wei)?,
                l2_gas_price: NonzeroGasPrice::MIN,
            },
            strk_gas_prices: GasPriceVector {
                l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_fri)?,
                l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_fri)?,
                l2_gas_price: NonzeroGasPrice::MIN,
            },
        },
        use_kzg_da,
    };

    let chain_info = ChainInfo {
        chain_id,
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: contract_address!(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea"
            ),
            eth_fee_token_address: contract_address!(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea"
            ),
        }, /* cf. https://docs.starknet.io/tools/important-addresses/
            * fee_token_addresses: FeeTokenAddresses {
            *     strk_fee_token_address: contract_address!(
            *         "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
            *     ),
            *     eth_fee_token_address: contract_address!(
            *         "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
            *     ),
            * }, */
    };

    // IMPORTANT:
    // The versioned constant must match the version that the block was executed with.
    // In this case, the versioned constant that Katana is using.
    const SN_VERSION: StarknetVersion = StarknetVersion::V0_13_3; // v0.13.3
    let versioned_constants = VersionedConstants::get(&SN_VERSION).unwrap();
    let bouncer_config = BouncerConfig::max();

    Ok(BlockContext::new(block_info, chain_info, versioned_constants.clone(), bouncer_config))
}

#[cfg(test)]
mod tests {

    use starknet::core::types::{Felt, ResourcePrice};
    use starknet_api::core::ChainId;

    use super::*;

    #[test]
    fn test_build_block_context_with_zero_gas_prices() {
        let chain_id = ChainId::Mainnet;
        // We don't really care about most of the fields.
        // What's important here is to set to zero different gas prices
        let block = BlockWithTxs {
            status: starknet::core::types::BlockStatus::AcceptedOnL1,
            block_hash: Felt::ZERO,
            parent_hash: Felt::ZERO,
            block_number: 1,
            new_root: Felt::ZERO,
            timestamp: 0,
            sequencer_address: Felt::ZERO,
            l1_gas_price: ResourcePrice { price_in_wei: Felt::ZERO, price_in_fri: Felt::ZERO },
            l1_data_gas_price: ResourcePrice { price_in_wei: Felt::ZERO, price_in_fri: Felt::ZERO },
            l1_da_mode: L1DataAvailabilityMode::Blob,
            starknet_version: String::from("0.13.2.1"),
            transactions: vec![],
        };

        let starknet_version = StarknetVersion::V0_13_2_1;

        // Call this function must not fail
        let block_context = build_block_context(chain_id, &block, starknet_version).unwrap();

        // Verify that gas prices were set to NonZeroU128::MIN
        assert_eq!(block_context.block_info().gas_prices.eth_gas_prices.l1_gas_price, NonzeroGasPrice::MIN);
        assert_eq!(block_context.block_info().gas_prices.strk_gas_prices.l1_gas_price, NonzeroGasPrice::MIN);
        assert_eq!(block_context.block_info().gas_prices.eth_gas_prices.l1_data_gas_price, NonzeroGasPrice::MIN);
        assert_eq!(block_context.block_info().gas_prices.eth_gas_prices.l1_data_gas_price, NonzeroGasPrice::MIN);
    }

    #[test]
    fn test_build_block_context_with_custom_gas_prices() {
        let chain_id = ChainId::Mainnet;

        // Expected values for gas price
        let wei_l1_price = 1234;
        let fri_l1_price = 5678;
        let wei_l1_data_price = 9012;
        let fri_l1_data_price = 3456;

        let block = BlockWithTxs {
            status: starknet::core::types::BlockStatus::AcceptedOnL1,
            block_hash: Felt::ZERO,
            parent_hash: Felt::ZERO,
            block_number: 1,
            new_root: Felt::ZERO,
            timestamp: 0,
            sequencer_address: Felt::ZERO,
            l1_gas_price: ResourcePrice {
                price_in_wei: Felt::from(wei_l1_price),
                price_in_fri: Felt::from(fri_l1_price),
            },
            l1_data_gas_price: ResourcePrice {
                price_in_wei: Felt::from(wei_l1_data_price),
                price_in_fri: Felt::from(fri_l1_data_price),
            },
            l1_da_mode: L1DataAvailabilityMode::Blob,
            starknet_version: String::from("0.13.2.1"),
            transactions: vec![],
        };

        let starknet_version = StarknetVersion::V0_13_2_1;
        let block_context = build_block_context(chain_id, &block, starknet_version).unwrap();

        // Verify that gas prices match our input values
        assert_eq!(block_context.block_info().gas_prices.eth_gas_prices.l1_gas_price.get(), GasPrice(wei_l1_price));
        assert_eq!(block_context.block_info().gas_prices.strk_gas_prices.l1_gas_price.get(), GasPrice(fri_l1_price));
        assert_eq!(
            block_context.block_info().gas_prices.eth_gas_prices.l1_data_gas_price.get(),
            GasPrice(wei_l1_data_price)
        );
        assert_eq!(
            block_context.block_info().gas_prices.strk_gas_prices.l1_data_gas_price.get(),
            GasPrice(fri_l1_data_price)
        );
    }
}
