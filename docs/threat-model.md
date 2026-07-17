# Threat model

## Goal

Run hostile, unattested core WebAssembly without giving it a direct primary channel for exporting
data. The scheduler and its sandbox are attested; the startup worker module is intentionally not.
The practical purpose is evidence that the operator cannot silently give a worker an identifying or
output-bearing host interface.

## Guaranteed boundary

Workers have computation and private linear memory only. They receive no input, identity, imports,
WASI, environment, inherited descriptors, filesystem, network, clock, randomness, threads, or
shared memory. The only callable ABI is `run: () -> ()`; all guest results and diagnostics are
discarded.

There is no public upload route. At startup the trusted scheduler makes one redirect-free HTTPS GET
to a secret URL, bounds the response, and requires a valid versioned AES-256-GCM envelope under a
separate 256-bit secret key. A third secret is sent only as a sensitive HTTPS bearer-authorization
header. It stores the decrypted module and its SHA-256 only in memory and removes all startup secrets
from the environment before creating runtime threads. Tinfoil egress and the scheduler's URL parser
independently restrict the pull to `artifacts.kkbr.ai` over HTTPS port 443; the scheduler makes no
further outbound request, and runner seccomp permits no network syscall.

After global admission, trusted policy selects a fixed one-second slot before parsing begins. The
runner is terminated at its deadline and the scheduler retains the slot permit until that deadline.
Validation failure, instantiation failure, early completion, trap, fuel exhaustion, runner failure,
and deadline termination all return HTTP 200 with the same serialized response at the slot release.
Caller disconnect does not cancel the slot task.

The child buffers bounded bytes, clears its environment, closes every descriptor above stderr,
applies no-new-privileges and rlimits, enters a filesystem-denying Landlock domain, installs a
kill-by-default seccomp allowlist, and only then parses and instantiates the module.

## Explicitly accepted risk

Queue and admission timing, denial of service within fixed limits, CPU caches, memory bandwidth,
branch predictors, TLBs, allocator behavior, process creation, CPU frequency, thermals, SMT, and
other scheduler or microarchitectural side channels may leak information. Fixed slots reduce a
worker's direct completion-time alphabet but do not eliminate these channels. No claim of constant
time, non-interference, or Spectre resistance is made.

Workers receive no identifying information, so a side channel can at most expose state already
present in or inferable through the shared execution environment; it is not given a tenant identity
or response payload to export directly. Host compromise, kernel or confidential-VM compromise,
sandbox/runtime vulnerabilities, availability, and traffic analysis outside the endpoint are also
outside the guarantee.

## Trusted computing base

The production TCB is the scheduler request/admission path, runner launcher, sandbox setup,
`wasmparser`, the `wasmi` interpreter, the kernel controls, and the attested container configuration.
Benchmark profiles, roles, synthetic-bit controls, experiment APIs, the benchmark client, and the
synthetic benchmark guest are excluded from the production image.
