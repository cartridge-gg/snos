// Gas Cost.
// See documentation in core/os/constants.cairo.

pub const STEP_GAS_COST: u64 = 100;
pub const RANGE_CHECK_GAS_COST: u64 = 70;
pub const KECCAK_BUILTIN_GAS_COST: u64 = 136189;
pub const PEDERSEN_GAS_COST: u64 = 4050;
pub const BITWISE_BUILTIN_GAS_COST: u64 = 583;
pub const ECOP_GAS_COST: u64 = 4085;
pub const POSEIDON_GAS_COST: u64 = 491;
pub const ADD_MOD_GAS_COST: u64 = 230;
pub const MUL_MOD_GAS_COST: u64 = 604;
pub const ECDSA_GAS_COST: u64 = 10561;
pub const MEMORY_HOLE_GAS_COST: u64 = 10;

pub const BLOCK_HASH_CONTRACT_ADDRESS: u64 = 1;

// An estimation of the initial gas for a transaction to run with. This solution is temporary and
// this value will become a field of the transaction.
#[allow(unused)]
pub const INITIAL_GAS_COST: u64 = 10_u64.pow(8) * STEP_GAS_COST;
// Compiler gas costs.
pub const ENTRY_POINT_INITIAL_BUDGET: u64 = 100 * STEP_GAS_COST;
// The initial gas budget for a system call (this value is hard-coded by the compiler).
// This needs to be high enough to cover OS costs in the case of failure due to out of gas.
pub const SYSCALL_BASE_GAS_COST: u64 = 100 * STEP_GAS_COST;
// OS gas costs.
pub const ENTRY_POINT_GAS_COST: u64 = ENTRY_POINT_INITIAL_BUDGET + 500 * STEP_GAS_COST;
#[allow(unused)]
pub const FEE_TRANSFER_GAS_COST: u64 = ENTRY_POINT_GAS_COST + 100 * STEP_GAS_COST;
#[allow(unused)]
pub const TRANSACTION_GAS_COST: u64 = (2 * ENTRY_POINT_GAS_COST) + FEE_TRANSFER_GAS_COST + (100 * STEP_GAS_COST);
// The required gas for each syscall.
pub const CALL_CONTRACT_GAS_COST: u64 = 15 * RANGE_CHECK_GAS_COST + 866 * STEP_GAS_COST;
pub const DEPLOY_GAS_COST: u64 = 7 * PEDERSEN_GAS_COST + 18 * RANGE_CHECK_GAS_COST + 1132 * STEP_GAS_COST;
pub const EMIT_EVENT_GAS_COST: u64 = SYSCALL_BASE_GAS_COST;
pub const GET_BLOCK_HASH_GAS_COST: u64 = 2 * RANGE_CHECK_GAS_COST + 104 * STEP_GAS_COST;
pub const GET_EXECUTION_INFO_GAS_COST: u64 = SYSCALL_BASE_GAS_COST;
#[allow(unused)]
pub const KECCAK_GAS_COST: u64 = SYSCALL_BASE_GAS_COST;
#[allow(unused)]
pub const KECCAK_ROUND_COST_GAS_COST: u64 =
    6 * BITWISE_BUILTIN_GAS_COST + KECCAK_BUILTIN_GAS_COST + 56 * RANGE_CHECK_GAS_COST + 281 * STEP_GAS_COST;
#[allow(unused)]
pub const LIBRARY_CALL_GAS_COST: u64 = 15 * RANGE_CHECK_GAS_COST + 842 * STEP_GAS_COST;
#[allow(unused)]
pub const REPLACE_CLASS_GAS_COST: u64 = 1 * RANGE_CHECK_GAS_COST + 104 * STEP_GAS_COST;
#[allow(unused)]
pub const SHA256_PROCESS_BLOCK_GAS_COST: u64 =
    1115 * BITWISE_BUILTIN_GAS_COST + 65 * RANGE_CHECK_GAS_COST + 1865 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256K1_ADD_GAS_COST: u64 = 29 * RANGE_CHECK_GAS_COST + 410 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256K1_GET_POINT_FROM_X_GAS_COST: u64 = 30 * RANGE_CHECK_GAS_COST + 395 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256K1_GET_XY_GAS_COST: u64 = 11 * RANGE_CHECK_GAS_COST + 207 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256K1_MUL_GAS_COST: u64 = 7045 * RANGE_CHECK_GAS_COST + 76505 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256K1_NEW_GAS_COST: u64 = 35 * RANGE_CHECK_GAS_COST + 461 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256R1_ADD_GAS_COST: u64 = 57 * RANGE_CHECK_GAS_COST + 593 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256R1_GET_POINT_FROM_X_GAS_COST: u64 = 44 * RANGE_CHECK_GAS_COST + 514 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256R1_GET_XY_GAS_COST: u64 = 11 * RANGE_CHECK_GAS_COST + 209 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256R1_MUL_GAS_COST: u64 = 13961 * RANGE_CHECK_GAS_COST + 125344 * STEP_GAS_COST;
#[allow(unused)]
pub const SECP256R1_NEW_GAS_COST: u64 = 49 * RANGE_CHECK_GAS_COST + 580 * STEP_GAS_COST;

#[allow(unused)]
pub const SEND_MESSAGE_TO_L1_GAS_COST: u64 = 1 * RANGE_CHECK_GAS_COST + 141 * STEP_GAS_COST;
#[allow(unused)]
pub const STORAGE_READ_GAS_COST: u64 = SYSCALL_BASE_GAS_COST;
#[allow(unused)]
pub const STORAGE_WRITE_GAS_COST: u64 = SYSCALL_BASE_GAS_COST;
pub const KECCAK_FULL_RATE_IN_U64S: u64 = 17;
// This constant represents an error message for invalid input length.
// The hexadecimal string "0x000000000000000000000000496e76616c696420696e707574206c656e677468"
// decodes to "Invalid input length".
pub const INVALID_INPUT_LENGTH_ERROR: &str = "0x000000000000000000000000496e76616c696420696e707574206c656e677468";
