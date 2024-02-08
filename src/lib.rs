pub mod config;
pub mod error;
pub mod execution;
pub mod hints;
pub mod io;
pub mod sharp;
pub mod state;
pub mod utils;

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use bincode::enc::write::Writer;
use blockifier::block_context::BlockContext;
use blockifier::state::state_api::StateReader;
use blockifier::transaction::objects::TransactionExecutionInfo;
use cairo_vm::cairo_run::{self, CairoRunConfig};
use cairo_vm::types::program::Program;
use cairo_vm::vm::errors::vm_exception::VmException;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use config::StarknetGeneralConfig;
use error::SnOsError;
use execution::deprecated_syscall_handler::DeprecatedOsSyscallHandlerWrapper;
use execution::helper::ExecutionHelperWrapper;
use io::output::StarknetOsOutput;
use state::SharedState;

//use katana_primitives::block::BlockTag;

pub struct SnOsRunner {
    // CairoVM layout type(default `starknet_with_keccak`)
    layout: String,
    // Path to compiled os program (default `build/os_latest.json`)
    os_path: String,
    // Path to StarknetOsInput JSON (default `build/input.json`)
    input_path: String,
    // Block context to run against
    pub block_context: BlockContext,
}

impl SnOsRunner {
    pub fn run(
        &self,
        shared_state: SharedState<impl StateReader>,
        execution_infos: Vec<TransactionExecutionInfo>,
    ) -> Result<CairoPie, SnOsError> {
        // Init CairoRunConfig
        let cairo_run_config = CairoRunConfig {
            layout: self.layout.as_str(),
            relocate_mem: true,
            trace_enabled: true,
            ..Default::default()
        };

        // Load the Starknet OS Program
        let starknet_os = fs::read(&self.os_path).map_err(|e| SnOsError::CatchAll(format!("{e}")))?;
        let program = Program::from_bytes(&starknet_os, Some(cairo_run_config.entrypoint))
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // Init cairo runner
        let mut cairo_runner = CairoRunner::new(&program, cairo_run_config.layout, cairo_run_config.proof_mode)
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // Setup Execution Helper
        let exec_helper = ExecutionHelperWrapper::new(execution_infos, &shared_state.block_context);

        // Init the Cairo VM
        let mut vm = VirtualMachine::new(cairo_run_config.trace_enabled);
        let end = cairo_runner.initialize(&mut vm, false).map_err(|e| SnOsError::Runner(e.into()))?;

        // Setup Depsyscall Handler
        let dep_syscall_ptr = vm.add_memory_segment();
        cairo_runner.exec_scopes.insert_value(
            "deprecated_syscall_handler",
            DeprecatedOsSyscallHandlerWrapper::new(exec_helper.clone(), dep_syscall_ptr),
        );

        // Setup Globals
        cairo_runner.exec_scopes.insert_value("input_path", self.input_path.clone());
        cairo_runner.exec_scopes.insert_box("block_context", Box::new(shared_state.block_context.clone()));
        cairo_runner.exec_scopes.insert_value("execution_helper", exec_helper);

        // Run the Cairo VM
        let mut sn_hint_processor = hints::SnosHintProcessor::default();
        cairo_runner
            .run_until_pc(end, &mut vm, &mut sn_hint_processor)
            .map_err(|err| VmException::from_vm_error(&cairo_runner, &vm, err))
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // End the Cairo VM run
        cairo_runner
            .end_run(cairo_run_config.disable_trace_padding, false, &mut vm, &mut sn_hint_processor)
            .map_err(|e| SnOsError::Runner(e.into()))?;

        if cairo_run_config.proof_mode {
            cairo_runner.finalize_segments(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        }

        // Prepare and check expected output.
        let _os_output = StarknetOsOutput::from_run(&vm)?;

        println!("{:?}", _os_output);

        vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.read_return_values(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.relocate(&mut vm, cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

        // Parse the Cairo VM output
        let pie = cairo_runner.get_cairo_pie(&vm).map_err(|e| SnOsError::PieParsing(format!("{e}")))?;

        Ok(pie)
    }

    pub fn with_layout(layout: &str) -> Self {
        Self { layout: layout.to_string(), ..Self::default() }
    }

    pub fn with_os_path(os_path: &str) -> Self {
        Self { os_path: os_path.to_string(), ..Self::default() }
    }

    pub fn with_input_path(input_path: &str) -> Self {
        Self { input_path: input_path.to_string(), ..Self::default() }
    }

    pub fn with_block_context(block_context: BlockContext) -> Self {
        Self { block_context, ..Self::default() }
    }
}

impl Default for SnOsRunner {
    fn default() -> Self {
        Self {
            layout: config::DEFAULT_LAYOUT.to_string(),
            os_path: config::DEFAULT_COMPILED_OS.to_string(),
            input_path: config::DEFAULT_INPUT_PATH.to_string(),
            block_context: StarknetGeneralConfig::default().empty_block_context(),
        }
    }
}

struct FileWriter {
    buf_writer: std::io::BufWriter<std::fs::File>,
    bytes_written: usize,
}

impl Writer for FileWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        self.buf_writer
            .write_all(bytes)
            .map_err(|e| bincode::error::EncodeError::Io { inner: e, index: self.bytes_written })?;

        self.bytes_written += bytes.len();

        Ok(())
    }
}

impl FileWriter {
    fn new(buf_writer: std::io::BufWriter<std::fs::File>) -> Self {
        Self { buf_writer, bytes_written: 0 }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buf_writer.flush()
    }
}

impl SnOsRunner {
    pub fn run_stone_compatible(
        &self,
        shared_state: SharedState<impl StateReader>,
        execution_infos: Vec<TransactionExecutionInfo>,
    ) -> Result<(), SnOsError> {
        // Init CairoRunConfig
        let cairo_run_config = CairoRunConfig {
            layout: self.layout.as_str(),
            relocate_mem: true,
            trace_enabled: true,
            proof_mode: true,
            ..Default::default()
        };

        // Load the Starknet OS Program
        let starknet_os = fs::read(&self.os_path).map_err(|e| SnOsError::CatchAll(format!("{e}")))?;
        let program = Program::from_bytes(&starknet_os, Some(cairo_run_config.entrypoint))
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // Init cairo runner
        let mut cairo_runner = CairoRunner::new(&program, cairo_run_config.layout, cairo_run_config.proof_mode)
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // Setup Execution Helper
        let exec_helper = ExecutionHelperWrapper::new(execution_infos, &shared_state.block_context);

        // Init the Cairo VM
        let mut vm = VirtualMachine::new(cairo_run_config.trace_enabled);
        let end = cairo_runner.initialize(&mut vm, false).map_err(|e| SnOsError::Runner(e.into()))?;

        // Setup Depsyscall Handler
        let dep_syscall_ptr = vm.add_memory_segment();
        cairo_runner.exec_scopes.insert_value(
            "deprecated_syscall_handler",
            DeprecatedOsSyscallHandlerWrapper::new(exec_helper.clone(), dep_syscall_ptr),
        );

        // Setup Globals
        cairo_runner.exec_scopes.insert_value("input_path", self.input_path.clone());
        cairo_runner.exec_scopes.insert_box("block_context", Box::new(shared_state.block_context.clone()));
        cairo_runner.exec_scopes.insert_value("execution_helper", exec_helper);

        // Run the Cairo VM
        let mut sn_hint_processor = hints::SnosHintProcessor::default();
        cairo_runner
            .run_until_pc(end, &mut vm, &mut sn_hint_processor)
            .map_err(|err| VmException::from_vm_error(&cairo_runner, &vm, err))
            .map_err(|e| SnOsError::Runner(e.into()))?;

        // End the Cairo VM run
        cairo_runner
            .end_run(cairo_run_config.disable_trace_padding, false, &mut vm, &mut sn_hint_processor)
            .map_err(|e| SnOsError::Runner(e.into()))?;

        if cairo_run_config.proof_mode {
            cairo_runner.finalize_segments(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        }

        // Prepare and check expected output.
        let _os_output = StarknetOsOutput::from_run(&vm)?;

        println!("{:?}", _os_output);

        vm.verify_auto_deductions().map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.read_return_values(&mut vm).map_err(|e| SnOsError::Runner(e.into()))?;
        cairo_runner.relocate(&mut vm, cairo_run_config.relocate_mem).map_err(|e| SnOsError::Runner(e.into()))?;

        let trace_file = Some(PathBuf::from("resources/main_trace.bin"));
        let memory_file = Some(PathBuf::from("resources/main_memory.bin"));
        let air_public_input = Some(PathBuf::from("resources/main_public_input.json"));
        let air_private_input = Some(PathBuf::from("resources/main_private_input.json"));

        if let Some(ref trace_path) = trace_file {
            let relocated_trace = cairo_runner.relocated_trace.as_ref().unwrap();

            let trace_file = std::fs::File::create(trace_path)?;
            let mut trace_writer = FileWriter::new(std::io::BufWriter::with_capacity(3 * 1024 * 1024, trace_file));

            cairo_run::write_encoded_trace(relocated_trace, &mut trace_writer).unwrap();
            trace_writer.flush()?;
        }

        if let Some(ref memory_path) = memory_file {
            let memory_file = std::fs::File::create(memory_path)?;
            let mut memory_writer = FileWriter::new(std::io::BufWriter::with_capacity(5 * 1024 * 1024, memory_file));

            cairo_run::write_encoded_memory(&cairo_runner.relocated_memory, &mut memory_writer).unwrap();
            memory_writer.flush()?;
        }

        if let Some(file_path) = air_public_input {
            let json = cairo_runner.get_air_public_input(&vm).unwrap().serialize_json().unwrap();
            std::fs::write(file_path, json)?;
        }

        if let (Some(file_path), Some(ref trace_file), Some(ref memory_file)) =
        (air_private_input, trace_file, memory_file)
    {
        // Get absolute paths of trace_file & memory_file
        let trace_path = trace_file
            .as_path()
            .canonicalize()
            .unwrap_or(trace_file.clone())
            .to_string_lossy()
            .to_string();
        let memory_path = memory_file
            .as_path()
            .canonicalize()
            .unwrap_or(memory_file.clone())
            .to_string_lossy()
            .to_string();

        let json = cairo_runner
            .get_air_private_input(&vm)
            .to_serializable(trace_path, memory_path)
            .serialize_json().unwrap();
        std::fs::write(file_path, json)?;
    }

        Ok(())
    }
}
