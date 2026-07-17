# Ishtar Oxide

Ishtar Oxide is a deliberately small scheduler for running untrusted, unattested core WebAssembly
modules inside an attested container. Its primary guarantee is narrow: a worker cannot directly
exfiltrate data through network, host calls, files, inherited state, a result body, or its own
success/failure status.

Timing and microarchitectural side channels remain plausible. Fixed execution slots make direct
self-timing channels coarser and noisier; they are not a non-interference proof.

## Boundary

- At startup, the scheduler reads a secret HTTPS URL, bearer API token, and AES-256-GCM key, pulls
  one encrypted artifact, authenticates and decrypts it in memory, and records the plaintext SHA-256.
- There is no upload or module-selection route. `POST /v1/run` invokes the startup module's exported
  `run: () -> ()` and discards its outcome.
- Every admitted run owns one global slot for exactly one second. Overruns are killed; early exit,
  validation failure, trap, fuel exhaustion, and timeout all produce the same response at the slot
  deadline.
- The guest receives no arguments, imports, WASI, environment, clocks, network, shared memory,
  filesystem, inherited descriptors, response data, or worker/session identifiers.
- Hostile bytes are parsed only after descriptor closure, environment clearing, rlimits,
  no-new-privileges, Landlock, and seccomp are installed in a fresh runner process.
- A single compiled policy sets fuel, memory, module-size, queue, concurrency, and slot limits.
  Benchmark profiles and experiment APIs are not present in the deployed image.

The old leakage client and synthetic guest remain as research artifacts under `crates/bench-*`, but
the scheduler does not depend on them and the container does not package them.

See [the threat model](docs/threat-model.md) and
[Tinfoil deployment guide](docs/running-on-tinfoil.md).
