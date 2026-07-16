use anyhow::{Context, Result, anyhow, bail};
use ishtar_protocol::{ExperimentProfile, RuntimeProfile, WorkerRole, sha256_hex};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use wasmi::{Config, Engine, Linker, Module, Store};
use wasmparser::{ExternalKind, FuncType, Parser, Payload, ValType, Validator};

#[derive(Debug, Clone)]
pub struct WasmLimits {
    pub max_memory_pages: u32,
}

#[derive(Clone)]
pub struct LoadedModule {
    pub sha256_hex: String,
    pub path: PathBuf,
    engine: Engine,
    module: Module,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WorkerInput {
    pub role: WorkerRole,
    pub bit: u8,
    pub trial_id: u64,
    pub profile_word: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerOutput {
    pub result: i32,
    pub fuel_consumed: u64,
}

pub fn load_restricted_module(path: &Path, limits: &WasmLimits) -> Result<LoadedModule> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read benchmark module {}", path.display()))?;
    validate_restricted_bytes(&bytes, limits)?;
    let engine = build_engine()?;
    let module = Module::new(&engine, &bytes[..]).context("compile validated module")?;
    Ok(LoadedModule {
        sha256_hex: sha256_hex(&bytes),
        path: path.to_path_buf(),
        engine,
        module,
    })
}

pub fn validate_restricted_bytes(bytes: &[u8], limits: &WasmLimits) -> Result<()> {
    Validator::new()
        .validate_all(bytes)
        .context("invalid core WebAssembly")?;

    let mut types: Vec<FuncType> = Vec::new();
    let mut function_types: Vec<u32> = Vec::new();
    let mut turn_function_index = None;
    let mut memory_count = 0usize;
    let mut has_start = false;

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.context("parse core WebAssembly")? {
            Payload::TypeSection(reader) => {
                for ty in reader.into_iter_err_on_gc_types() {
                    types.push(ty.context("unsupported GC type")?);
                }
            }
            Payload::ImportSection(reader) => {
                if reader.count() != 0 {
                    bail!("guest imports are forbidden");
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    function_types.push(ty.context("invalid function type index")?);
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory.context("invalid memory declaration")?;
                    memory_count += 1;
                    if memory.shared || memory.memory64 || memory.page_size_log2.is_some() {
                        bail!("shared, memory64, and custom-page memories are forbidden");
                    }
                    let max = memory
                        .maximum
                        .ok_or_else(|| anyhow!("memory maximum is required"))?;
                    if memory.initial > limits.max_memory_pages as u64
                        || max > limits.max_memory_pages as u64
                    {
                        bail!("guest memory exceeds configured page limit");
                    }
                }
            }
            Payload::TableSection(reader) if reader.count() != 0 => bail!("tables are forbidden"),
            Payload::TagSection(reader) if reader.count() != 0 => {
                bail!("exception tags are forbidden")
            }
            Payload::StartSection { .. } => has_start = true,
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.context("invalid export")?;
                    match (export.name, export.kind) {
                        ("turn", ExternalKind::Func) => {
                            if turn_function_index.replace(export.index).is_some() {
                                bail!("duplicate turn export");
                            }
                        }
                        ("memory", ExternalKind::Memory)
                        | ("__data_end", ExternalKind::Global)
                        | ("__heap_base", ExternalKind::Global) => {}
                        _ => bail!("unexpected guest export: {}", export.name),
                    }
                }
            }
            Payload::ComponentSection { .. }
            | Payload::ComponentInstanceSection(_)
            | Payload::ComponentAliasSection(_)
            | Payload::ComponentTypeSection(_)
            | Payload::ComponentCanonicalSection(_)
            | Payload::ComponentStartSection { .. }
            | Payload::ComponentImportSection(_)
            | Payload::ComponentExportSection(_) => {
                bail!("WebAssembly components are forbidden")
            }
            _ => {}
        }
    }
    if has_start {
        bail!("start functions are forbidden");
    }
    if memory_count != 1 {
        bail!("guest must declare exactly one bounded memory");
    }
    let function_index =
        turn_function_index.ok_or_else(|| anyhow!("missing turn export"))? as usize;
    let type_index = *function_types
        .get(function_index)
        .ok_or_else(|| anyhow!("turn function index is out of bounds"))?
        as usize;
    let ty = types
        .get(type_index)
        .ok_or_else(|| anyhow!("turn type index is out of bounds"))?;
    if ty.params() != [ValType::I32; 5] || ty.results() != [ValType::I32] {
        bail!("turn must have signature (i32,i32,i32,i32,i32)->i32");
    }
    Ok(())
}

pub fn execute_turn(
    module: &LoadedModule,
    input: WorkerInput,
    profile: &ExperimentProfile,
) -> Result<WorkerOutput> {
    let mut store = Store::new(&module.engine, ());
    store
        .set_fuel(profile.turn_fuel)
        .context("enable turn fuel")?;
    let linker = Linker::new(&module.engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module.module)
        .context("instantiate restricted guest")?;
    let turn = instance
        .get_typed_func::<(i32, i32, i32, i32, i32), i32>(&store, "turn")
        .context("resolve turn ABI")?;
    let result = turn
        .call(
            &mut store,
            (
                input.role.abi_value(),
                i32::from(input.bit),
                input.trial_id as i32,
                (input.trial_id >> 32) as i32,
                input.profile_word as i32,
            ),
        )
        .context("execute guest turn")?;
    let remaining = store.get_fuel().context("read remaining fuel")?;
    Ok(WorkerOutput {
        result,
        fuel_consumed: profile.turn_fuel.saturating_sub(remaining),
    })
}

pub fn build_engine() -> Result<Engine> {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .wasm_multi_memory(false)
        .wasm_reference_types(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false)
        .wasm_custom_page_sizes(false)
        .wasm_wide_arithmetic(false);
    Ok(Engine::new(&config))
}

pub fn runtime_profile() -> RuntimeProfile {
    RuntimeProfile {
        wasm_engine: "wasmi-2.0.0-beta.7-portable-interpreter".into(),
        interpreter_only: true,
        wasi_enabled: false,
        imports_enabled: false,
        threads_enabled: false,
        shared_memory_enabled: false,
        clocks_available_to_guest: false,
        runner_process_per_turn: true,
        linux_seccomp_requested: cfg!(target_os = "linux"),
        linux_seccomp_applied: cfg!(target_os = "linux"),
        linux_landlock_requested: cfg!(target_os = "linux"),
        linux_landlock_applied: false,
        no_new_privs_applied: cfg!(target_os = "linux"),
        rlimits_applied: cfg!(target_os = "linux"),
        sandbox_notes: if cfg!(target_os = "linux") {
            vec![
                "fresh process, no-new-privileges, and rlimits enabled".into(),
                "fail-closed seccomp allowlist enabled for every guest runner".into(),
                "Landlock is requested but not yet applied".into(),
            ]
        } else {
            vec!["fresh process enabled; Linux sandbox controls unavailable on this host".into()]
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate(wat_source: &str, pages: u32) -> Result<()> {
        let bytes = wat::parse_str(wat_source)?;
        validate_restricted_bytes(
            &bytes,
            &WasmLimits {
                max_memory_pages: pages,
            },
        )
    }

    const VALID: &str = r#"(module
      (memory (export "memory") 1 2)
      (func (export "turn") (param i32 i32 i32 i32 i32) (result i32) i32.const 0))"#;

    #[test]
    fn accepts_tiny_restricted_module() {
        validate(VALID, 2).unwrap();
    }

    #[test]
    fn rejects_import_start_and_excess_memory() {
        assert!(validate(r#"(module (import "x" "y" (func)))"#, 2).is_err());
        assert!(
            validate(
                r#"(module (memory 1 2) (func $s) (start $s)
          (func (export "turn") (param i32 i32 i32 i32 i32) (result i32) i32.const 0))"#,
                2
            )
            .is_err()
        );
        assert!(
            validate(
                r#"(module (memory 1 9)
          (func (export "turn") (param i32 i32 i32 i32 i32) (result i32) i32.const 0))"#,
                2
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_wrong_signature_and_unexpected_export() {
        assert!(
            validate(
                r#"(module (memory 1 2)
          (func (export "turn") (param i32) (result i32) i32.const 0))"#,
                2
            )
            .is_err()
        );
        assert!(
            validate(
                r#"(module (memory 1 2) (func (export "other"))
          (func (export "turn") (param i32 i32 i32 i32 i32) (result i32) i32.const 0))"#,
                2
            )
            .is_err()
        );
    }
}
