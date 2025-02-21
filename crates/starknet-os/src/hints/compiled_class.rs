use std::collections::HashMap;
use std::rc::Rc;

use cairo_lang_starknet_classes::NestedIntList;
use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_maybe_relocatable_from_var_name, get_relocatable_from_var_name,
    insert_value_from_var_name, insert_value_into_ap,
};
use cairo_vm::hint_processor::hint_processor_definition::{HintExtension, HintProcessor, HintReference};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::vm_core::VirtualMachine;
use cairo_vm::{any_box, Felt252};
use indoc::indoc;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::cairo_types::structs::{CompiledClass, CompiledClassFact};
use crate::hints::vars;
use crate::io::classes::{create_bytecode_segment_structure, load_casm_entrypoints};
use crate::io::input::StarknetOsInput;
use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
    BytecodeSegment, BytecodeSegmentStructureImpl,
};
use crate::utils::custom_hint_error;

pub const GUESS_CLASS_FACTS: &str = indoc! {r#"
    from starkware.starknet.core.os.contract_class.compiled_class_hash import (
        create_bytecode_segment_structure,
        get_compiled_class_struct,
    )

    ids.n_compiled_class_facts = len(os_input.compiled_classes)
    ids.compiled_class_facts = (compiled_class_facts_end := segments.add())
    for i, (compiled_class_hash, compiled_class) in enumerate(
        os_input.compiled_classes.items()
    ):
        # Load the compiled class.
        cairo_contract = get_compiled_class_struct(
            identifiers=ids._context.identifiers,
            compiled_class=compiled_class,
            # Load the entire bytecode - the unaccessed segments will be overriden and skipped
            # after the execution, in `validate_compiled_class_facts_post_execution`.
            bytecode=compiled_class.bytecode,
        )
        segments.load_data(
            ptr=ids.compiled_class_facts[i].address_,
            data=(compiled_class_hash, segments.gen_arg(cairo_contract))
        )

        bytecode_ptr = ids.compiled_class_facts[i].compiled_class.bytecode_ptr
        # Compiled classes are expected to end with a `ret` opcode followed by a pointer to
        # the builtin costs.
        segments.load_data(
            ptr=bytecode_ptr + cairo_contract.bytecode_length,
            data=[0x208b7fff7fff7ffe, ids.builtin_costs]
        )

        # Load hints and debug info.
        vm_load_program(
            compiled_class.get_runnable_program(entrypoint_builtins=[]), bytecode_ptr)"#
};

pub fn guess_class_facts(
    _: &dyn HintProcessor,
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<HintExtension, HintError> {
    let mut hint_extension = HintExtension::new();

    // ids.n_compiled_class_facts = len(os_input.compiled_classes)
    let os_input: Rc<StarknetOsInput> = exec_scopes.get::<Rc<StarknetOsInput>>(vars::scopes::OS_INPUT)?.clone();
    insert_value_from_var_name(
        vars::ids::N_COMPILED_CLASS_FACTS,
        os_input.compiled_classes.len(),
        vm,
        ids_data,
        ap_tracking,
    )?;

    // ids.compiled_class_facts = (compiled_class_facts_end := segments.add())
    let compiled_class_facts_ptr = vm.add_memory_segment();
    insert_value_from_var_name(vars::ids::COMPILED_CLASS_FACTS, compiled_class_facts_ptr, vm, ids_data, ap_tracking)?;

    // let mut next_class_facts_ptr = compiled_class_facts_ptr;
    for (i, (hash, class)) in os_input.compiled_classes.iter().enumerate() {
        // Load the compiled class.

        let class = class.clone().to_cairo_lang_contract_class().map_err(|e| custom_hint_error(e.to_string()))?;

        // cairo_contract = get_compiled_class_struct(
        //     identifiers=ids._context.identifiers,
        //     compiled_class=compiled_class,
        //     # Load the entire bytecode - the unaccessed segments will be overriden and skipped
        //     # after the execution, in `validate_compiled_class_facts_post_execution`.
        //     bytecode=compiled_class.bytecode,
        // )
        let contract_base_addr = vm.add_memory_segment();
        {
            // CompiledClass struct layout in memory:
            // [0] compiled_class_version - Version identifier for the compiled class format
            // [1] n_external_functions - Number of external functions
            // [2] external_functions - Pointer to external functions data
            // [3] n_l1_handlers - Number of L1 handler functions
            // [4] l1_handlers - Pointer to L1 handler functions data
            // [5] n_constructors - Number of constructor functions
            // [6] constructors - Pointer to constructor functions data
            // [7] bytecode_length - Length of the contract bytecode
            // [8] bytecode_ptr - Pointer to contract bytecode segment

            // Set the compiled class version identifier (COMPILED_CLASS_V1)
            let version = Felt252::from_hex("0x434f4d50494c45445f434c4153535f5631").unwrap();
            vm.insert_value(contract_base_addr, version)?; // [0]

            // Convert class to Cairo lang format and load entry points

            // Load external function entry points at [1] (len) and [2] (data)
            load_casm_entrypoints(vm, (contract_base_addr + 1)?, &class.entry_points_by_type.external)?;
            // Load L1 handler entry points at [3] (len) and [4] (data)
            load_casm_entrypoints(vm, (contract_base_addr + 3)?, &class.entry_points_by_type.l1_handler)?;

            // Load constructor entry points at [5] (len) and [6] (data)
            load_casm_entrypoints(vm, (contract_base_addr + 5)?, &class.entry_points_by_type.constructor)?;

            // CompiledClass

            // Convert bytecode to Felt252 format
            let bytecode: Vec<Felt252> = class.bytecode.iter().map(|x| Felt252::from(&x.value)).collect();
            let bytecode: Vec<MaybeRelocatable> = bytecode.into_iter().map(MaybeRelocatable::from).collect();

            // Create new segment for bytecode and store pointer at [8]
            let bytecode_base_addr = vm.add_memory_segment();
            dbg!(&bytecode_base_addr);
            vm.load_data(bytecode_base_addr, &bytecode)?;
            vm.insert_value((contract_base_addr + 7)?, Felt252::from(bytecode.len()))?;
            vm.insert_value((contract_base_addr + 8)?, bytecode_base_addr)?;

            let ret_opcode = Felt252::from_hex("0x208b7fff7fff7ffe").unwrap();
            let builtin_costs =
                get_maybe_relocatable_from_var_name(vars::ids::BUILTIN_COSTS, vm, ids_data, ap_tracking)?;
            vm.load_data((bytecode_base_addr + bytecode.len())?, &[ret_opcode.into(), builtin_costs])?;

            for (rel_pc, hints) in class.hints {
                let hint_ptr = Relocatable::from((bytecode_base_addr.segment_index, rel_pc));
                hint_extension.insert(hint_ptr, hints.iter().map(|h| any_box!(h.clone())).collect());
            }
        }

        // segments.load_data(
        //     ptr=ids.compiled_class_facts[i].address_,
        //     data=(compiled_class_hash, segments.gen_arg(cairo_contract))
        // )
        //
        // The Cairo definition of the CompiledClassFact struct:
        //
        // A list entry that maps a hash to the corresponding contract classes.
        // struct CompiledClassFact {
        //     // The hash of the contract. This member should be first, so that we can lookup items
        //     // with the hash as key, using find_element().
        //     hash: felt,
        //     compiled_class: CompiledClass*,
        // }
        //

        vm.load_data(
            dbg!((compiled_class_facts_ptr + (CompiledClassFact::cairo_size() * i))?),
            &[dbg!(hash.into()), contract_base_addr.into()],
        )?;
    }

    Ok(hint_extension)
}

pub const VALIDATE_COMPILED_CLASS_FACTS: &str = indoc! {r#"
    from starkware.cairo.lang.vm.relocatable import RelocatableValue

    bytecode_segment_to_length = {}
    compiled_hash_to_bytecode_segment = {}
    for i in range(ids.n_compiled_class_facts):
        fact = ids.compiled_class_facts[i]
        bytecode_segment = fact.compiled_class.bytecode_ptr.segment_index
        bytecode_segment_to_length[bytecode_segment] = fact.compiled_class.bytecode_length
        compiled_hash_to_bytecode_segment[fact.hash] = bytecode_segment

    bytecode_segment_to_visited_pcs = {
        bytecode_segment: [] for bytecode_segment in bytecode_segment_to_length
    }
    for addr in iter_accessed_addresses():
        if (
            isinstance(addr, RelocatableValue)
            and addr.segment_index in bytecode_segment_to_visited_pcs
        ):
            bytecode_segment_to_visited_pcs[addr.segment_index].append(addr.offset)

    # Sort and remove the program extra data, which is not part of the hash.
    for bytecode_segment, visited_pcs in bytecode_segment_to_visited_pcs.items():
        visited_pcs.sort()
        while (
            len(visited_pcs) > 0
            and visited_pcs[-1] >= bytecode_segment_to_length[bytecode_segment]
        ):
            visited_pcs.pop()

    # Build the bytecode segment structures based on the execution info.
    bytecode_segment_structures = {
        compiled_hash: create_bytecode_segment_structure(
            bytecode=compiled_class.bytecode,
            bytecode_segment_lengths=compiled_class.bytecode_segment_lengths,
            visited_pcs=bytecode_segment_to_visited_pcs[
                compiled_hash_to_bytecode_segment[compiled_hash]
            ],
        ) for compiled_hash, compiled_class in os_input.compiled_classes.items()
    }"#
};

pub fn validate_compiled_class_facts(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let n_compiled_class_facts =
        get_integer_from_var_name(vars::ids::N_COMPILED_CLASS_FACTS, vm, ids_data, ap_tracking)?;
    let n_compiled_class_facts = n_compiled_class_facts.to_usize().expect("valid usize");

    let compiled_class_facts_ptr =
        get_relocatable_from_var_name(vars::ids::COMPILED_CLASS_FACTS, vm, ids_data, ap_tracking)?;
    let compiled_class_facts_ptr = vm.get_relocatable(compiled_class_facts_ptr)?;

    let mut compiled_hash_to_bytecode_segment: HashMap<Felt252, Relocatable> = HashMap::new();
    let mut bytecode_segment_to_length: HashMap<Relocatable, Felt252> = HashMap::new();

    for i in 0..n_compiled_class_facts {
        let fact = (compiled_class_facts_ptr + (CompiledClassFact::cairo_size() * i))?;

        let compiled_hash = vm.get_integer((fact + CompiledClassFact::hash_offset())?)?;
        let compiled_class = vm.get_relocatable((fact + CompiledClassFact::compiled_class_offset())?)?;

        let bytecode_len = vm.get_integer((compiled_class + CompiledClass::bytecode_length_offset())?)?;
        let bytecode_segment = vm.get_relocatable((compiled_class + CompiledClass::bytecode_ptr_offset())?)?;

        bytecode_segment_to_length.insert(bytecode_segment.clone(), *bytecode_len);
        compiled_hash_to_bytecode_segment.insert(compiled_hash.into_owned(), bytecode_segment);
    }

    let mut bytecode_segment_to_visited_pcs =
        bytecode_segment_to_length.keys().fold(HashMap::new(), |mut acc, bytecode_segment| {
            acc.insert(bytecode_segment.clone(), Vec::new());
            acc
        });

    for (bytecode_segment, visited_pcs) in &mut bytecode_segment_to_visited_pcs {
        visited_pcs.sort();
        while visited_pcs.len() > 0 && visited_pcs[visited_pcs.len()] >= bytecode_segment_to_length[bytecode_segment] {
            visited_pcs.pop();
        }
    }

    // bytecode_segment_structures = {
    //         compiled_hash: create_bytecode_segment_structure(
    //             bytecode=compiled_class.bytecode,
    //             bytecode_segment_lengths=compiled_class.bytecode_segment_lengths,
    //             visited_pcs=bytecode_segment_to_visited_pcs[
    //                 compiled_hash_to_bytecode_segment[compiled_hash]
    //             ],
    //         ) for compiled_hash, compiled_class in os_input.compiled_classes.items()
    // }

    let os_input: Rc<StarknetOsInput> = exec_scopes.get::<Rc<StarknetOsInput>>(vars::scopes::OS_INPUT)?.clone();
    let mut scoped_bytecode_segment_structures: HashMap<Felt252, BytecodeSegmentStructureImpl> = HashMap::new();

    for (compiled_hash, compiled_class) in &os_input.compiled_classes {
        let class =
            compiled_class.clone().to_cairo_lang_contract_class().map_err(|e| custom_hint_error(e.to_string()))?;

        let bytecode: Vec<BigUint> = class.bytecode.iter().map(|x| x.value.clone()).collect();
        let bytecode_segment_lengths = class.bytecode_segment_lengths.unwrap_or(NestedIntList::Leaf(bytecode.len()));

        let bytecode_segment = compiled_hash_to_bytecode_segment.get(&compiled_hash).unwrap();
        let visited_pcs = bytecode_segment_to_visited_pcs.get(&bytecode_segment).cloned();

        let bytecode_segment_structure =
            create_bytecode_segment_structure(&bytecode, bytecode_segment_lengths, visited_pcs)?;

        scoped_bytecode_segment_structures.insert(*compiled_hash, bytecode_segment_structure);
    }

    exec_scopes.insert_value(vars::scopes::BYTECODE_SEGMENT_STRUCTURES, scoped_bytecode_segment_structures);

    Ok(())
}

pub const DELETE_MEMORY: &str = "del memory.data[ids.data_ptr]";

pub fn delete_memory(
    vm: &mut VirtualMachine,
    _: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let data_ptr = get_relocatable_from_var_name(vars::ids::DATA_PTR, vm, ids_data, ap_tracking)?;
    let data_ptr = vm.get_relocatable(data_ptr)?;
    vm.segments.memory.clear_cell(data_ptr)?;
    Ok(())
}

pub const START_CALCULATE_COMPILED_CLASS_HASH: &str = indoc! {r#"
    vm_enter_scope({
        "bytecode_segment_structure": bytecode_segment_structures[ids.compiled_class_fact.hash]
    })"#
};

pub fn start_calculate_compiled_class_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structures: HashMap<Felt252, BytecodeSegmentStructureImpl> =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURES)?;

    let compiled_fact = get_relocatable_from_var_name(vars::ids::COMPILED_CLASS_FACT, vm, ids_data, ap_tracking)?;
    let compiled_hash = vm.get_integer((compiled_fact + CompiledClassFact::hash_offset())?)?;

    let bytecode_segment_structure = bytecode_segment_structures
        .get(&compiled_hash)
        .ok_or(custom_hint_error(format!("missing bytecode segment structure for {:#x}", *compiled_hash)))?
        .clone();

    exec_scopes.enter_scope(HashMap::from([(
        vars::scopes::BYTECODE_SEGMENT_STRUCTURE.to_string(),
        any_box!(bytecode_segment_structure),
    )]));

    Ok(())
}

pub const END_CALCULATE_COMPILED_CLASS_HASH: &str = indoc! {r#"
    vm_exit_scope()

    computed_hash = ids.hash
    expected_hash = ids.compiled_class_fact.hash
    assert computed_hash == expected_hash, (
        "Computed compiled_class_hash is inconsistent with the hash in the os_input. "
        f"Computed hash = {computed_hash}, Expected hash = {expected_hash}.")"#
};

pub fn end_calculate_compiled_class_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    exec_scopes.exit_scope()?;

    let computed_hash = get_integer_from_var_name(vars::ids::HASH, vm, ids_data, ap_tracking)?;
    let expected_hash = {
        let compiled_class_fact =
            get_relocatable_from_var_name(vars::ids::COMPILED_CLASS_FACT, vm, ids_data, ap_tracking)?;
        *vm.get_integer((compiled_class_fact + CompiledClassFact::hash_offset())?)?
    };

    assert_eq!(
        computed_hash, expected_hash,
        "Computed compiled_class_hash is inconsistent with the hash in the os_input. \n
        Computed hash = {computed_hash:#x}, Expected hash = {expected_hash:#x}."
    );

    Ok(())
}

pub const ASSIGN_BYTECODE_SEGMENTS: &str = indoc! {r#"
    bytecode_segments = iter(bytecode_segment_structure.segments)"#
};

pub fn assign_bytecode_segments(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentStructureImpl =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    let bytecode_segments = match bytecode_segment_structure {
        BytecodeSegmentStructureImpl::SegmentedNode(segmented_node) => segmented_node.segments.into_iter(),
        BytecodeSegmentStructureImpl::Leaf(_) => {
            return Err(HintError::AssertionFailed("Expected SegmentedNode".to_string().into_boxed_str()));
        }
    };

    exec_scopes.insert_value(vars::scopes::BYTECODE_SEGMENTS, bytecode_segments);

    Ok(())
}

pub const ASSERT_END_OF_BYTECODE_SEGMENTS: &str = indoc! {r#"
    assert next(bytecode_segments, None) is None"#
};
pub fn assert_end_of_bytecode_segments(
    _vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segments =
        exec_scopes.get_mut_ref::<<Vec<BytecodeSegment> as IntoIterator>::IntoIter>(vars::scopes::BYTECODE_SEGMENTS)?;
    // ensure the iter is exhausted. note that this consumes next() if it is not
    if bytecode_segments.next().is_some() {
        return Err(HintError::AssertionFailed("bytecode_segments is not exhausted".to_string().into_boxed_str()));
    }

    Ok(())
}

pub const ITER_CURRENT_SEGMENT_INFO: &str = indoc! {r#"
    current_segment_info = next(bytecode_segments)

    is_used = current_segment_info.is_used
    ids.is_segment_used = 1 if is_used else 0

    is_used_leaf = is_used and isinstance(current_segment_info.inner_structure, BytecodeLeaf)
    ids.is_used_leaf = 1 if is_used_leaf else 0

    ids.segment_length = current_segment_info.segment_length
    vm_enter_scope(new_scope_locals={
        "bytecode_segment_structure": current_segment_info.inner_structure,
    })"#
};
pub fn iter_current_segment_info(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segments =
        exec_scopes.get_mut_ref::<<Vec<BytecodeSegment> as IntoIterator>::IntoIter>(vars::scopes::BYTECODE_SEGMENTS)?;

    let current_segment_info =
        bytecode_segments.next().expect("Expected more bytecode segments (asserted in previous hint)");

    let is_used = current_segment_info.is_used;
    let is_used_felt = if is_used { Felt252::ONE } else { Felt252::ZERO };
    insert_value_from_var_name(vars::ids::IS_SEGMENT_USED, is_used_felt, vm, ids_data, ap_tracking)?;

    let is_leaf = matches!(current_segment_info.inner_structure, BytecodeSegmentStructureImpl::Leaf(_));
    let is_used_leaf = is_used && is_leaf;
    let is_used_leaf_felt = if is_used_leaf { Felt252::ONE } else { Felt252::ZERO };
    insert_value_from_var_name(vars::ids::IS_USED_LEAF, is_used_leaf_felt, vm, ids_data, ap_tracking)?;

    let segment_length: Felt252 = current_segment_info.segment_length.0.into();
    insert_value_from_var_name(vars::ids::SEGMENT_LENGTH, segment_length, vm, ids_data, ap_tracking)?;

    exec_scopes.enter_scope(HashMap::from([(
        vars::scopes::BYTECODE_SEGMENT_STRUCTURE.to_string(),
        any_box!(current_segment_info.inner_structure),
    )]));

    Ok(())
}

pub const SET_AP_TO_SEGMENT_HASH: &str = indoc! {r#"
    memory[ap] = to_felt_or_relocatable(bytecode_segment_structure.hash())"#
};

pub fn set_ap_to_segment_hash(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let bytecode_segment_structure: BytecodeSegmentStructureImpl =
        exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE)?;

    // Calc hash
    let hash = bytecode_segment_structure.hash().map_err(|err| custom_hint_error(err.to_string()))?;

    // Insert to ap
    insert_value_into_ap(vm, Felt252::from(hash))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use cairo_vm::any_box;
    use cairo_vm::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
    use num_bigint::BigUint;
    use rstest::rstest;

    use super::*;
    use crate::starknet::core::os::contract_class::compiled_class_hash_objects::{
        BytecodeLeaf, BytecodeSegmentStructureImpl, BytecodeSegmentedNode,
    };
    use crate::starkware_utils::commitment_tree::base_types::Length;

    #[test]
    fn test_bytecode_segment_hints() {
        // tests both ASSIGN_BYTECODE_SEGMENTS and ASSERT_END_OF_BYTECODE_SEGMENTS. The first
        // should prepare an iterater and put it in ExecutionScopes, the second should ensure that
        // the iterator is exhausted.

        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::new();

        let mut exec_scopes: ExecutionScopes = Default::default();

        // execution scopes must have a BytecodeSegmentStructureImpl inserted. We insert one that has one
        // segment which lets us test both success and failure of ASSERT_END_OF_BYTECODE_SEGMENTS.
        let segments = vec![BytecodeSegment {
            segment_length: Length(0),
            is_used: false,
            inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: Default::default() }),
        }];
        let segment_structure = BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode { segments });
        exec_scopes.insert_box(vars::scopes::BYTECODE_SEGMENT_STRUCTURE, any_box!(segment_structure));

        assign_bytecode_segments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        // iter is not empty, so the next call should fail. notice that it will consume next(),
        // though.
        let res = assert_end_of_bytecode_segments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants);
        assert!(res.is_err());
        match res.unwrap_err() {
            HintError::AssertionFailed(msg) => {
                assert_eq!(msg, "bytecode_segments is not exhausted".to_string().into_boxed_str())
            }
            _ => panic!("Unexpected error returned"),
        }

        // should succeed this time because iter as exhausted
        let res = assert_end_of_bytecode_segments(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants);
        assert!(res.is_ok());
    }

    #[test]
    fn test_set_ap_to_segment_hash() {
        use num_bigint::BigUint;

        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(2);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();
        let ids_data = HashMap::new();

        let mut exec_scopes: ExecutionScopes = Default::default();

        // Execution scopes must have a BytecodeSegmentStructureImpl inserted. We insert one that has one
        let segments = vec![BytecodeSegment {
            segment_length: Length(1),
            is_used: false,
            inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: vec![BigUint::from(1u8)] }),
        }];
        let segment_structure = BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode { segments });
        exec_scopes.insert_box(vars::scopes::BYTECODE_SEGMENT_STRUCTURE, any_box!(segment_structure));

        set_ap_to_segment_hash(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();

        // Read hash and compare with expected hash
        let hash = vm.get_integer(vm.get_ap()).unwrap().into_owned();
        assert_eq!(hex::encode(hash.to_bytes_be()), "064b3967128647f5db91e107897e7e6d72f2a06f35d01d19055a7f85c85e65ba");
    }

    #[test]
    fn test_hash_bytecode_leaf() {
        // Reference hashes were taken from cairo-lang (compiled_class_hash_test.py)
        // In order to test these or any other leaf in Python use this:
        // print("Leaf hash: ", hex(BytecodeLeaf(data=[1,2,3])))
        use num_bigint::BigUint;

        // Let's create a simple BytecodeLeaf with just one element [1] in data field
        let leaf = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: vec![BigUint::from(0x01u8)] });
        assert_eq!(
            hex::encode(leaf.hash().unwrap().deref()),
            "00579e8877c7755365d5ec1ec7d3a94a457eff5d1f40482bbe9729c064cdead2"
        );

        // Now try with a BytecodeLeaf that contains 3 elements [1,2,3] in data field
        let leaf = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
            data: vec![BigUint::from(0x01u8), BigUint::from(0x02u8), BigUint::from(0x03u8)],
        });
        assert_eq!(
            hex::encode(leaf.hash().unwrap().deref()),
            "02f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad082"
        );

        // Finally, use a more complex leaf data = [1,2,3, 100, 500, 1000, 123456789]
        let leaf = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
            data: vec![
                BigUint::from(1u8),
                BigUint::from(2u8),
                BigUint::from(3u8),
                BigUint::from(100u8),
                BigUint::from(500u16),
                BigUint::from(1000u16),
                BigUint::from(123456789u64),
            ],
        });
        assert_eq!(
            hex::encode(leaf.hash().unwrap().deref()),
            "0061992871ada0f904463047841a564ad8ed8f4fae20e9e68a0debee876cfdb3"
        );
    }

    #[test]
    fn test_hash_bytecode_node() {
        // Reference hashes were taken from cairo-lang (compiled_class_hash_test.py)
        // In order to test these or any other leaf in Python use this:
        // segment_list = [BytecodeSegment(segment_length=1, is_used=False,
        // inner_structure=BytecodeLeaf(data=[1, 2]))] print("Node hash:",
        // hex(BytecodeSegmentedNode(segments=segment_list))) Keep in mind that inner_structure can
        // be a BytecodeLeaf or another BytecodeSegment

        // A BytecodeSegmentedNode is just a vector of BytecodeSegment. Let's create different combinations
        // and check that the hash function is working

        // Check hash when the segments is just one leaf
        let inner_struct = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf { data: vec![BigUint::from(0x01u8)] });
        let seg = vec![BytecodeSegment { segment_length: Length(1), is_used: false, inner_structure: inner_struct }];
        let node = BytecodeSegmentedNode { segments: seg };
        assert_eq!(
            hex::encode(node.hash().unwrap().deref()),
            "064b3967128647f5db91e107897e7e6d72f2a06f35d01d19055a7f85c85e65ba"
        );

        // Check hash when the segments is one leaf with several elements
        let inner_struct = BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
            data: vec![BigUint::from(0x01u8), BigUint::from(0x02u8)],
        });
        let seg = vec![BytecodeSegment { segment_length: Length(2), is_used: false, inner_structure: inner_struct }];
        let node = BytecodeSegmentedNode { segments: seg };
        assert_eq!(
            hex::encode(node.hash().unwrap().deref()),
            "073542be7740dc970b59f6e05e7a065586a493b59932a3a88adc902a626da18d"
        );

        // Check hash when the segments are a combination between Nodes and Leafs. This was extracted from
        // Python code. To extract this example use these lines in pytest file:
        // print("BytecodeSegmentedNode: ", bytecode_segment_structure)
        // print("BytecodeSegmentedNode hash: ", hex(bytecode_segment_structure.hash()))

        // Output from pytest:
        // BytecodeSegmentedNode:
        // BytecodeSegmentedNode(segments=[
        // BytecodeSegment(segment_length=3, is_used=False, inner_structure=BytecodeLeaf(data=[1, 2, 3])),

        // BytecodeSegment(segment_length=3, is_used=False, inner_structure=
        //  BytecodeSegmentedNode(segments=[
        //      BytecodeSegment(segment_length=1, is_used=False, inner_structure=BytecodeLeaf(data=[4])),
        //      BytecodeSegment(segment_length=1, is_used=False, inner_structure=BytecodeLeaf(data=[5])),
        //      BytecodeSegment(segment_length=1, is_used=False, inner_structure=
        //          BytecodeSegmentedNode(segments=[BytecodeSegment(segment_length=1, is_used=False,
        //              inner_structure=BytecodeLeaf(data=[6]))]))])),

        // BytecodeSegment(segment_length=4, is_used=False, inner_structure=BytecodeLeaf(data=[7, 8, 9,
        // 10])) ])

        let node = BytecodeSegmentedNode {
            segments: vec![
                // 1st segment
                BytecodeSegment {
                    segment_length: Length(3),
                    is_used: false,
                    inner_structure: {
                        BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                            data: vec![BigUint::from(1u8), BigUint::from(2u8), BigUint::from(3u8)],
                        })
                    },
                },
                // 2nd segment
                BytecodeSegment {
                    segment_length: Length(3),
                    is_used: true,
                    inner_structure: {
                        BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode {
                            segments: vec![
                                BytecodeSegment {
                                    segment_length: Length(1),
                                    is_used: true,
                                    inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                                        data: vec![BigUint::from(4u8)],
                                    }),
                                },
                                BytecodeSegment {
                                    segment_length: Length(1),
                                    is_used: false,
                                    inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                                        data: vec![BigUint::from(5u8)],
                                    }),
                                },
                                BytecodeSegment {
                                    segment_length: Length(1),
                                    is_used: true,
                                    inner_structure: BytecodeSegmentStructureImpl::SegmentedNode(
                                        BytecodeSegmentedNode {
                                            segments: vec![BytecodeSegment {
                                                segment_length: Length(1),
                                                is_used: true,
                                                inner_structure: BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                                                    data: vec![BigUint::from(6u8)],
                                                }),
                                            }],
                                        },
                                    ),
                                },
                            ],
                        })
                    },
                },
                // 3rd segment
                BytecodeSegment {
                    segment_length: Length(4),
                    is_used: false,
                    inner_structure: {
                        BytecodeSegmentStructureImpl::Leaf(BytecodeLeaf {
                            data: vec![BigUint::from(7u8), BigUint::from(8u8), BigUint::from(9u8), BigUint::from(10u8)],
                        })
                    },
                },
            ],
        };

        assert_eq!(
            hex::encode(node.hash().unwrap().deref()),
            "06dc9a5436f10ef82ff99457f4af9dd5a5794713c1ed272b4e82e9a8d9ccb32e"
        );
    }

    #[rstest]
    #[case(BytecodeSegment {
        segment_length: Length(3),
        is_used: true,
        inner_structure: BytecodeSegmentStructureImpl::Leaf(
            BytecodeLeaf {data: vec![BigUint::from(1u8), BigUint::from(2u8), BigUint::from(3u8)]})
    })]
    #[case(BytecodeSegment {
        segment_length: Length(1),
        is_used: false,
        inner_structure: BytecodeSegmentStructureImpl::Leaf(
            BytecodeLeaf {data: vec![BigUint::from(123u8)]})
    })]
    #[case(BytecodeSegment {
        segment_length: Length(1),
        is_used: false,
        inner_structure: BytecodeSegmentStructureImpl::SegmentedNode(BytecodeSegmentedNode {
            segments: vec![BytecodeSegment {
                segment_length: Length(2),
                is_used: true,
                inner_structure: BytecodeSegmentStructureImpl::Leaf(
                    BytecodeLeaf {data: vec![BigUint::from(123u8)]})
            }]
        })
    })]
    fn test_iter_current_segment_info(#[case] segment: BytecodeSegment) {
        let mut vm = VirtualMachine::new(false);
        vm.add_memory_segment();
        vm.add_memory_segment();
        vm.set_fp(3);

        let ap_tracking = ApTracking::new();
        let constants = HashMap::new();

        let ids_data = HashMap::from([
            (vars::ids::SEGMENT_LENGTH.to_string(), HintReference::new_simple(-3)),
            (vars::ids::IS_SEGMENT_USED.to_string(), HintReference::new_simple(-2)),
            (vars::ids::IS_USED_LEAF.to_string(), HintReference::new_simple(-1)),
        ]);

        let mut exec_scopes: ExecutionScopes = Default::default();
        let segments = vec![segment.clone()];

        exec_scopes.insert_value::<<Vec<BytecodeSegment> as IntoIterator>::IntoIter>(
            vars::scopes::BYTECODE_SEGMENTS,
            segments.into_iter(),
        );

        iter_current_segment_info(&mut vm, &mut exec_scopes, &ids_data, &ap_tracking, &constants).unwrap();
        let bytecode_segment_structure: BytecodeSegmentStructureImpl =
            exec_scopes.get(vars::scopes::BYTECODE_SEGMENT_STRUCTURE).unwrap();

        // Verify is_used field from testing segment
        let is_used = get_integer_from_var_name(vars::ids::IS_SEGMENT_USED, &vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(segment.is_used, is_used == Felt252::ONE);

        // Verify segment_length field from testing segment
        let segment_length =
            get_integer_from_var_name(vars::ids::SEGMENT_LENGTH, &vm, &ids_data, &ap_tracking).unwrap();
        assert_eq!(Felt252::from(segment.segment_length.0), segment_length);

        // Verify that both segment.inner_structure  and bytecode_segment_structure are the same type
        let is_leaf = matches!(segment.inner_structure, BytecodeSegmentStructureImpl::Leaf(_))
            && matches!(bytecode_segment_structure, BytecodeSegmentStructureImpl::Leaf(_));
        let is_segmented_node = matches!(segment.inner_structure, BytecodeSegmentStructureImpl::SegmentedNode(_))
            && matches!(bytecode_segment_structure, BytecodeSegmentStructureImpl::SegmentedNode(_));
        assert!(is_leaf || is_segmented_node);
    }
}
