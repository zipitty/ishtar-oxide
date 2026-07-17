use anyhow::{Context, Result, bail};
use wasmi::{
    Config, EnforcedLimits, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};
use wasmparser::{Parser, Payload, Validator};
use zeroize::Zeroizing;

struct StoreState {
    limits: StoreLimits,
}

pub fn execute(
    module_bytes: &[u8],
    state: &[u8],
    role: i32,
    bit: i32,
    iterations: i32,
    fuel: u64,
    max_memory_pages: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    validate(module_bytes, max_memory_pages)?;
    let engine = engine();
    let module = Module::new(&engine, module_bytes).context("compile module")?;
    let limits = StoreLimitsBuilder::new()
        .memory_size(max_memory_pages as usize * 65_536)
        .memories(1)
        .instances(1)
        .tables(1)
        .table_elements(100_000)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, StoreState { limits });
    store.limiter(|store| &mut store.limits);
    store.set_fuel(fuel).context("set fuel")?;
    let instance = Linker::new(&engine)
        .instantiate_and_start(&mut store, &module)
        .context("instantiate module")?;
    let memory = instance
        .get_memory(&store, "memory")
        .context("module must export memory")?;
    if state.len() > memory.data(&store).len() {
        bail!("state exceeds guest memory");
    }
    memory.write(&mut store, 0, state).context("inject state")?;
    let run = instance
        .get_typed_func::<(i32, i32, i32, i32), i32>(&store, "run")
        .context("module must export run(i32,i32,i32,i32)->i32")?;
    let _ = run
        .call(&mut store, (role, bit, iterations, state.len() as i32))
        .context("execute run")?;
    let mut output = Zeroizing::new(vec![0; state.len()]);
    memory
        .read(&store, 0, &mut output)
        .context("extract state")?;
    memory.data_mut(&mut store).fill(0);
    Ok(output)
}

fn validate(bytes: &[u8], max_memory_pages: u32) -> Result<()> {
    Validator::new()
        .validate_all(bytes)
        .context("invalid core WebAssembly")?;
    let mut memories = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.context("parse core WebAssembly")? {
            Payload::ImportSection(reader) if reader.count() != 0 => bail!("imports are forbidden"),
            Payload::StartSection { .. } => bail!("start functions are forbidden"),
            Payload::MemorySection(reader) => {
                for memory in reader {
                    memories += 1;
                    let memory = memory.context("invalid memory")?;
                    if memory.shared || memory.memory64 || memory.page_size_log2.is_some() {
                        bail!("unsupported memory form");
                    }
                    if memory.initial > max_memory_pages as u64
                        || memory
                            .maximum
                            .is_some_and(|maximum| maximum > max_memory_pages as u64)
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
    if memories != 1 {
        bail!("exactly one memory is required");
    }
    Ok(())
}

fn engine() -> Engine {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .enforced_limits(EnforcedLimits::strict())
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
    fn fixture_round_trips_and_changes_fixed_state() {
        let module = wat::parse_str(include_str!("../fixtures/sequential_probe.wat")).unwrap();
        let input = vec![0x11; 64];
        let output = execute(&module, &input, 1, 0, 100, 1_000_000, 129).unwrap();
        assert_eq!(output.len(), input.len());
        assert!(output.iter().all(|byte| *byte == 0x4b));
    }

    #[test]
    fn rejects_start_and_imports() {
        let start = wat::parse_str(
            r#"(module
                (memory (export "memory") 1)
                (func $start)
                (start $start)
                (func (export "run") (param i32 i32 i32 i32) (result i32) i32.const 0))"#,
        )
        .unwrap();
        assert!(execute(&start, &[0; 1], 1, 0, 1, 1000, 1).is_err());
        let import = wat::parse_str(
            r#"(module
                (import "host" "f" (func))
                (memory (export "memory") 1)
                (func (export "run") (param i32 i32 i32 i32) (result i32) i32.const 0))"#,
        )
        .unwrap();
        assert!(execute(&import, &[0; 1], 1, 0, 1, 1000, 1).is_err());
    }
}
