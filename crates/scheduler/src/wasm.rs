use anyhow::{Context, Result, bail};
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmparser::{Parser, Payload, Validator};

struct StoreState {
    limits: StoreLimits,
}

/// Parses, instantiates, and executes hostile bytes. Call only after sandboxing.
pub fn execute(bytes: &[u8], fuel: u64, max_memory_pages: u32) -> Result<()> {
    validate(bytes, max_memory_pages)?;
    let engine = engine();
    let module = Module::new(&engine, bytes).context("compile module")?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(max_memory_pages as usize * 65_536)
        .memories(1)
        .instances(1)
        .tables(4)
        .table_elements(100_000)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, StoreState { limits });
    store.limiter(|state| &mut state.limits);
    store.set_fuel(fuel).context("set execution fuel")?;
    let instance = Linker::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .context("instantiate module")?;
    let run = instance
        .get_typed_func::<(), ()>(&store, "run")
        .context("module must export run: () -> ()")?;
    run.call(&mut store, ()).context("execute run")?;
    Ok(())
}

/// Enforces only the host boundary, not benchmark shape or application behavior.
fn validate(bytes: &[u8], max_memory_pages: u32) -> Result<()> {
    Validator::new()
        .validate_all(bytes)
        .context("invalid core WebAssembly")?;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.context("parse core WebAssembly")? {
            Payload::ImportSection(reader) if reader.count() != 0 => {
                bail!("imports are forbidden")
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory.context("invalid memory")?;
                    if memory.shared || memory.memory64 || memory.page_size_log2.is_some() {
                        bail!("shared, memory64, and custom-page memories are forbidden");
                    }
                    if memory.initial > max_memory_pages as u64
                        || memory
                            .maximum
                            .is_some_and(|max| max > max_memory_pages as u64)
                    {
                        bail!("memory exceeds policy");
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
            | Payload::ComponentExportSection(_) => bail!("components are forbidden"),
            _ => {}
        }
    }
    Ok(())
}

fn engine() -> Engine {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .wasm_multi_memory(false)
        .wasm_custom_page_sizes(false)
        .wasm_reference_types(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false)
        .wasm_wide_arithmetic(false);
    Engine::new(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_general_core_wasm_exports() {
        let bytes = wat::parse_str(
            r#"(module
                (memory 1 2)
                (global (export "application_state") (mut i32) (i32.const 7))
                (func (export "helper") (result i32) i32.const 9)
                (func (export "run")))"#,
        )
        .unwrap();
        execute(&bytes, 10_000, 2).unwrap();
    }

    #[test]
    fn rejects_host_imports_and_excess_memory() {
        let imported =
            wat::parse_str(r#"(module (import "host" "read" (func)) (func (export "run")))"#)
                .unwrap();
        assert!(execute(&imported, 10_000, 2).is_err());

        let large = wat::parse_str(r#"(module (memory 3) (func (export "run")))"#).unwrap();
        assert!(execute(&large, 10_000, 2).is_err());
    }

    #[test]
    fn rejects_missing_or_wrong_entrypoint_without_restricting_other_exports() {
        let missing = wat::parse_str(r#"(module (func (export "other")))"#).unwrap();
        assert!(execute(&missing, 10_000, 2).is_err());
        let wrong = wat::parse_str(r#"(module (func (export "run") (param i32)))"#).unwrap();
        assert!(execute(&wrong, 10_000, 2).is_err());
    }
}
