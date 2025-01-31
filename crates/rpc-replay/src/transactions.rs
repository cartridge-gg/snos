use std::str::FromStr;
use std::sync::Arc;

// use blockifier::blockifier::block::GasPrices;
// use blockifier::execution::contract_class::ClassInfo;
use blockifier::transaction::account_transaction::{AccountTransaction, ExecutionFlags};
use blockifier::transaction::errors::TransactionExecutionError;
use rpc_client::RpcClient;
use starknet::core::types::{
    BlockId, DeclareTransaction, DeclareTransactionV0, DeclareTransactionV1, DeclareTransactionV2,
    DeclareTransactionV3, DeployAccountTransaction, DeployAccountTransactionV1, DeployAccountTransactionV3, Felt,
    InvokeTransaction, InvokeTransactionV1, InvokeTransactionV3, L1HandlerTransaction, ResourceBoundsMapping,
    Transaction, TransactionTrace, TransactionTraceWithHash,
};
use starknet::providers::{Provider, ProviderError};
use starknet_api::block::GasPrices;
use starknet_api::contract_class::{ClassInfo, SierraVersion};
use starknet_api::core::{calculate_contract_address, ContractAddress, PatriciaKey};
use starknet_api::transaction::fields::{Fee, ResourceBounds, ValidResourceBounds};
use starknet_api::transaction::TransactionHash;
use starknet_api::StarknetApiError;
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::sierra_contract_class::GenericSierraContractClass;
use starknet_os_types::starknet_core_addons::LegacyContractDecompressionError;
use thiserror::Error;

use crate::utils::{felt_to_u128, FeltConversionError};

#[derive(Error, Debug)]
pub enum ToBlockifierError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] ProviderError),
    #[error("OS Contract Class Error: {0}")]
    StarknetContractClassError(#[from] starknet_os_types::error::ContractClassError),
    // #[error("Blockifier Contract Class Error: {0}")]
    // BlockifierContractClassError(#[from] blockifier::execution::errors::ContractClassError),
    #[error("Legacy Contract Decompression Error: {0}")]
    LegacyContractDecompressionError(#[from] LegacyContractDecompressionError),
    #[error("Starknet API Error: {0}")]
    StarknetApiError(#[from] StarknetApiError),
    #[error("Transaction Execution Error: {0}")]
    TransactionExecutionError(#[from] TransactionExecutionError),
    #[error("Felt Conversion Error: {0}")]
    FeltConversionError(#[from] FeltConversionError),
}

pub fn resource_bounds_core_to_api(resource_bounds: &ResourceBoundsMapping) -> ValidResourceBounds {
    ValidResourceBounds::L1Gas(ResourceBounds {
        max_amount: resource_bounds.l1_gas.max_amount.into(),
        max_price_per_unit: resource_bounds.l1_gas.max_price_per_unit.into(),
    })
}

fn da_mode_core_to_api(
    da_mode: starknet::core::types::DataAvailabilityMode,
) -> starknet_api::data_availability::DataAvailabilityMode {
    match da_mode {
        starknet::core::types::DataAvailabilityMode::L1 => starknet_api::data_availability::DataAvailabilityMode::L1,
        starknet::core::types::DataAvailabilityMode::L2 => starknet_api::data_availability::DataAvailabilityMode::L2,
    }
}

fn invoke_v1_to_blockifier(
    tx: &InvokeTransactionV1,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let charge_fee = tx.max_fee != Felt::ZERO;
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V1(starknet_api::transaction::InvokeTransactionV1 {
        max_fee: Fee(felt_to_u128(&tx.max_fee)?),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.to_vec())),
    });

    let tx = starknet_api::executable_transaction::InvokeTransaction { tx: api_tx, tx_hash };
    let tx = starknet_api::executable_transaction::AccountTransaction::Invoke(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

fn invoke_v3_to_blockifier(
    tx: &InvokeTransactionV3,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let charge_fee = !skip_charge_fee_if_zero_resource_bounds(&tx.resource_bounds);
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::InvokeTransaction::V3(starknet_api::transaction::InvokeTransactionV3 {
        resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
        tip: starknet_api::transaction::fields::Tip(tx.tip),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.to_vec()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.to_vec())),
        nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
        fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
        paymaster_data: starknet_api::transaction::fields::PaymasterData(tx.paymaster_data.to_vec()),
        account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
            tx.account_deployment_data.to_vec(),
        ),
    });

    let tx = starknet_api::executable_transaction::InvokeTransaction { tx: api_tx, tx_hash };
    let tx = starknet_api::executable_transaction::AccountTransaction::Invoke(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

/// Creates a ClassInfo instance from the given class hash by retrieving the contract class
/// from the Starknet RPC client and converting it to a Blockifier-compatible format.
/// Handle both Sierra and Legacy classes
async fn create_class_info(
    class_hash: Felt,
    client: &RpcClient,
    block_number: u64,
) -> Result<ClassInfo, ToBlockifierError> {
    // TODO: improve this to avoid retrieving this twice. Already done in lib.rs from prove_block
    let starknet_contract_class: starknet::core::types::ContractClass =
        client.starknet_rpc().get_class(BlockId::Number(block_number), class_hash).await?;

    let (blockifier_contract_class, program_length, abi_length, sierra_version) = match starknet_contract_class {
        starknet::core::types::ContractClass::Sierra(sierra) => {
            let generic_sierra = GenericSierraContractClass::from(sierra);
            let flattened_sierra = generic_sierra.clone().to_starknet_core_contract_class()?;
            let casm = generic_sierra.compile()?.get_cairo_lang_contract_class()?.clone();
            let sierra_version = SierraVersion::from_str(&casm.compiler_version)?;
            let contract_class = starknet_api::contract_class::ContractClass::V1(casm);

            (
                contract_class,
                // dbg!(flattened_sierra.sierra_program.len())
                1,
                0,
                sierra_version,
            )
        }

        starknet::core::types::ContractClass::Legacy(legacy) => {
            let generic_legacy = GenericDeprecatedCompiledClass::try_from(legacy)?;
            let contract_class = starknet_api::contract_class::ContractClass::V0(
                generic_legacy.get_starknet_api_contract_class()?.clone(),
            );

            (contract_class, 0, 0, SierraVersion::DEPRECATED)
        }
    };

    Ok(ClassInfo::new(&blockifier_contract_class, program_length, 0, sierra_version)?)
}

async fn declare_v0_to_blockifier(
    tx: &DeclareTransactionV0,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let charge_fee = tx.max_fee != Felt::ZERO;
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V0(starknet_api::transaction::DeclareTransactionV0V1 {
        max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce::default(),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
    });
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    let tx = starknet_api::executable_transaction::DeclareTransaction { tx: api_tx, tx_hash, class_info };
    let tx = starknet_api::executable_transaction::AccountTransaction::Declare(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

async fn declare_v1_to_blockifier(
    tx: &DeclareTransactionV1,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let charge_fee = tx.max_fee != Felt::ZERO;
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V1(starknet_api::transaction::DeclareTransactionV0V1 {
        max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
    });
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    let tx = starknet_api::executable_transaction::DeclareTransaction { tx: api_tx, tx_hash, class_info };
    let tx = starknet_api::executable_transaction::AccountTransaction::Declare(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

async fn declare_v2_to_blockifier(
    tx: &DeclareTransactionV2,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let charge_fee = tx.max_fee != Felt::ZERO;
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V2(starknet_api::transaction::DeclareTransactionV2 {
        max_fee: starknet_api::transaction::fields::Fee(felt_to_u128(&tx.max_fee)?),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
    });
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    let tx = starknet_api::executable_transaction::DeclareTransaction { tx: api_tx, tx_hash, class_info };
    let tx = starknet_api::executable_transaction::AccountTransaction::Declare(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

async fn declare_v3_to_blockifier(
    tx: &DeclareTransactionV3,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let charge_fee = dbg!(!skip_charge_fee_if_zero_resource_bounds(&tx.resource_bounds));
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeclareTransaction::V3(starknet_api::transaction::DeclareTransactionV3 {
        resource_bounds: dbg!(resource_bounds_core_to_api(dbg!(&tx.resource_bounds))),
        tip: starknet_api::transaction::fields::Tip(tx.tip),
        signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
        nonce: starknet_api::core::Nonce(tx.nonce),
        class_hash: starknet_api::core::ClassHash(tx.class_hash),
        compiled_class_hash: starknet_api::core::CompiledClassHash(tx.compiled_class_hash),
        sender_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.sender_address)?),
        nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
        fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
        paymaster_data: starknet_api::transaction::fields::PaymasterData(tx.paymaster_data.clone()),
        account_deployment_data: starknet_api::transaction::fields::AccountDeploymentData(
            tx.account_deployment_data.clone(),
        ),
    });
    let class_info = create_class_info(tx.class_hash, client, block_number).await?;
    let tx = starknet_api::executable_transaction::DeclareTransaction { tx: api_tx, tx_hash, class_info };
    let tx = starknet_api::executable_transaction::AccountTransaction::Declare(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

fn l1_handler_to_blockifier(
    tx: &L1HandlerTransaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::L1HandlerTransaction {
        version: starknet_api::transaction::TransactionVersion(tx.version),
        nonce: starknet_api::core::Nonce(Felt::from(tx.nonce)),
        contract_address: starknet_api::core::ContractAddress(PatriciaKey::try_from(tx.contract_address)?),
        entry_point_selector: starknet_api::core::EntryPointSelector(tx.entry_point_selector),
        calldata: starknet_api::transaction::fields::Calldata(Arc::new(tx.calldata.clone())),
    };

    let (l1_gas, l1_data_gas) = match &trace.trace_root {
        TransactionTrace::L1Handler(l1_handler) => (
            l1_handler.execution_resources.data_resources.data_availability.l1_gas,
            l1_handler.execution_resources.data_resources.data_availability.l1_data_gas,
        ),
        _ => unreachable!("Expected L1Handler type for TransactionTrace"),
    };

    let fee = match (l1_gas, l1_data_gas) {
        // There are the cases where both these values are zero and that means no matter what we multiply,
        // we will get a value of 0.
        // Having the fee as 0 for L1 handler will fail on the blockifier execution
        // Learn more:
        // https://github.com/starkware-libs/sequencer/blob/b5a877719dc2ce5b1ca833f14d9473c1f1c27059/crates/blockifier/src/transaction/transaction_execution.rs#L166
        // https://github.com/eqlabs/pathfinder/blob/eb81bf149fe516c3542a90a5c1715c5a3a141d0b/crates/rpc/src/executor.rs#L548
        // The comment(which is not very helpful) on the line above is:
        // // For now, assert only that any amount of fee was paid.
        // More investigations are recommended
        (0, 0) => 1_000_000_000_000u128,
        (0, l1_data_gas) => gas_prices.eth_gas_prices.l1_data_gas_price.get().0 * l1_data_gas as u128,
        (l1_gas, 0) => gas_prices.eth_gas_prices.l1_gas_price.get().0 * l1_gas as u128,
        _ => unreachable!("At least l1_gas or l1_data_gas must be zero"),
    };

    let paid_fee_on_l1 = Fee(fee);

    let tx = starknet_api::executable_transaction::L1HandlerTransaction { tx: api_tx, tx_hash, paid_fee_on_l1 };
    Ok(blockifier::transaction::transaction_execution::Transaction::L1Handler(tx))
}

/// Calculates a contract address for deploy transaction
fn recalculate_contract_address(
    api_tx: &starknet_api::transaction::DeployAccountTransaction,
) -> Result<ContractAddress, StarknetApiError> {
    calculate_contract_address(
        api_tx.contract_address_salt(),
        api_tx.class_hash(),
        &api_tx.constructor_calldata(),
        // When the contract is deployed via a DEPLOY_ACCOUNT transaction: 0
        ContractAddress::from(0_u8),
    )
}

fn deploy_account_v1_to_blockifier(
    tx: &DeployAccountTransactionV1,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let charge_fee = tx.max_fee != Felt::ZERO;
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);

    let (max_fee, signature, nonce, class_hash, constructor_calldata, contract_address_salt) = (
        Fee(felt_to_u128(&tx.max_fee)?),
        starknet_api::transaction::fields::TransactionSignature(tx.signature.to_vec()),
        starknet_api::core::Nonce(tx.nonce),
        starknet_api::core::ClassHash(tx.class_hash),
        starknet_api::transaction::fields::Calldata(Arc::new(tx.constructor_calldata.to_vec())),
        starknet_api::transaction::fields::ContractAddressSalt(tx.contract_address_salt),
    );
    let contract_address = calculate_contract_address(
        contract_address_salt,
        class_hash,
        &constructor_calldata,
        ContractAddress::default(),
    )?;

    let api_tx = starknet_api::transaction::DeployAccountTransaction::V1(
        starknet_api::transaction::DeployAccountTransactionV1 {
            max_fee,
            signature,
            nonce,
            class_hash,
            constructor_calldata,
            contract_address_salt,
        },
    );

    let tx = starknet_api::executable_transaction::DeployAccountTransaction { tx: api_tx, tx_hash, contract_address };
    let tx = starknet_api::executable_transaction::AccountTransaction::DeployAccount(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

fn deploy_account_v3_to_blockifier(
    tx: &DeployAccountTransactionV3,
) -> Result<blockifier::transaction::transaction_execution::Transaction, StarknetApiError> {
    let charge_fee = !skip_charge_fee_if_zero_resource_bounds(&tx.resource_bounds);
    let execution_flags = ExecutionFlags { charge_fee, ..Default::default() };

    let tx_hash = TransactionHash(tx.transaction_hash);
    let api_tx = starknet_api::transaction::DeployAccountTransaction::V3(
        starknet_api::transaction::DeployAccountTransactionV3 {
            resource_bounds: resource_bounds_core_to_api(&tx.resource_bounds),
            tip: starknet_api::transaction::fields::Tip(tx.tip),
            signature: starknet_api::transaction::fields::TransactionSignature(tx.signature.clone()),
            nonce: starknet_api::core::Nonce(tx.nonce),
            class_hash: starknet_api::core::ClassHash(tx.class_hash),
            contract_address_salt: starknet_api::transaction::fields::ContractAddressSalt(tx.contract_address_salt),
            constructor_calldata: starknet_api::transaction::fields::Calldata(Arc::new(
                tx.constructor_calldata.clone(),
            )),
            nonce_data_availability_mode: da_mode_core_to_api(tx.nonce_data_availability_mode),
            fee_data_availability_mode: da_mode_core_to_api(tx.fee_data_availability_mode),
            paymaster_data: starknet_api::transaction::fields::PaymasterData(tx.paymaster_data.clone()),
        },
    );
    let contract_address = recalculate_contract_address(&api_tx)?;

    let tx = starknet_api::executable_transaction::DeployAccountTransaction { tx: api_tx, tx_hash, contract_address };
    let tx = starknet_api::executable_transaction::AccountTransaction::DeployAccount(tx);

    Ok(blockifier::transaction::transaction_execution::Transaction::Account(AccountTransaction { tx, execution_flags }))
}

/// Maps starknet-core transactions to Blockifier-compatible types.
#[async_backtrace::framed]
pub async fn starknet_rs_to_blockifier(
    sn_core_tx: &starknet::core::types::Transaction,
    trace: &TransactionTraceWithHash,
    gas_prices: &GasPrices,
    client: &RpcClient,
    block_number: u64,
) -> Result<blockifier::transaction::transaction_execution::Transaction, ToBlockifierError> {
    let blockifier_tx = match sn_core_tx {
        Transaction::Invoke(tx) => match tx {
            InvokeTransaction::V0(_) => unimplemented!("starknet_rs_to_blockifier with InvokeTransaction::V0"),
            InvokeTransaction::V1(tx) => invoke_v1_to_blockifier(tx)?,
            InvokeTransaction::V3(tx) => invoke_v3_to_blockifier(tx)?,
        },
        Transaction::Declare(tx) => match tx {
            DeclareTransaction::V0(tx) => declare_v0_to_blockifier(tx, client, block_number).await?,
            DeclareTransaction::V1(tx) => declare_v1_to_blockifier(tx, client, block_number).await?,
            DeclareTransaction::V2(tx) => declare_v2_to_blockifier(tx, client, block_number).await?,
            DeclareTransaction::V3(tx) => declare_v3_to_blockifier(tx, client, block_number).await?,
        },
        Transaction::L1Handler(tx) => l1_handler_to_blockifier(tx, trace, gas_prices)?,
        Transaction::DeployAccount(tx) => match tx {
            DeployAccountTransaction::V1(tx) => deploy_account_v1_to_blockifier(tx)?,
            DeployAccountTransaction::V3(tx) => deploy_account_v3_to_blockifier(tx)?,
        },

        Transaction::Deploy(_) => {
            unimplemented!("we do not plan to support deprecated deploy txs, only deploy_account")
        }
    };

    Ok(blockifier_tx)
}

fn skip_charge_fee_if_zero_resource_bounds(resource_bounds: &ResourceBoundsMapping) -> bool {
    let l1_bounds = &resource_bounds.l1_gas;
    let max_amount: u128 = l1_bounds.max_amount.into();
    (max_amount * l1_bounds.max_price_per_unit) == 0
}
