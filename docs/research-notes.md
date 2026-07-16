# Related work

- **CT-Wasm** adds information-flow types for constant-time cryptographic WASM. It addresses secret-dependent guest behavior, while this lab intentionally runs a cooperating sender and measures the scheduler boundary.
- **Constant-Time Wasmtime** explores runtime support for constant-time execution. Wasmtime is a JIT and is not in the baseline trusted dependency set.
- **Swivel** hardens compiled WebAssembly against Spectre-style attacks. This lab starts with an interpreter and does not claim Spectre resistance.
- **WASM-MUTATE** and **CROW** diversify or synthesize semantically related WASM programs. They may be useful for later robustness suites, but mutation is not needed for the fixed public baseline guest.
- **Vivienne** analyzes constant-time properties of WebAssembly. Static constant-time verification is complementary to this empirical cross-session benchmark.
- **Enarx**, **Veracruz**, and **Twine** demonstrate WASM-in-TEE designs. They are architectural references rather than dependencies because the target is a portable Tinfoil container and nested KVM/microVM support is not assumed.

The baseline therefore stays small: structural validation with `wasmparser`, interpreted execution with `wasmi`, a fresh Linux process per turn, and container isolation. These works should be revisited as comparison profiles, not silently added to the trusted computing base.

