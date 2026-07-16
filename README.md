# Ishtar Oxide leakage lab

Ishtar Oxide is an auditable Rust laboratory for measuring cross-session timing and resource-contention leakage between parallel, restricted WebAssembly turns. It is the evidence-gathering precursor to a trusted scheduler library, not that production scheduler.

The lab accepts **synthetic bits only**. Never submit prompts, credentials, production data, or real secrets. Its public benchmark guest is intentionally cooperating/malicious and its parallel profiles intentionally create contention.

## Security boundary

- Anonymous sessions use independent 256-bit bearer capabilities; only SHA-256 token hashes remain in RAM.
- The guest is interpreted core WASM with no imports, WASI, clocks, files, network, randomness, threads, or shared memory.
- Every turn gets a fresh process, fixed fuel/memory/time limits, a fixed-size result field, and profile-controlled release quantization.
- Linux runners apply no-new-privileges, rlimits, and a fail-closed seccomp allowlist before guest instantiation. Runtime metadata reports each control; Landlock remains explicitly pending.
- Experiment lifecycle and trusted timing records require `LAB_ADMIN_TOKEN`; ordinary session APIs remain public.

## Deploy, then benchmark

Leakage measurements are meaningful only on the attested Tinfoil hardware and image being evaluated. Local builds and tests verify correctness; they are not benchmark results.

Publish and deploy the container using the pinned two-phase Tinfoil workflows. Then start Tinfoil's verified local proxy:

```bash
tinfoil container connect YOUR_CONTAINER_NAME --port 3301
```

Run the external-clock benchmark client through that attestation-verifying proxy:

```bash
LAB_ADMIN_TOKEN=replace-with-at-least-16-bytes cargo run -p ishtar-bench-client -- \
  run --base-url http://127.0.0.1:3301 --profile realistic \
  --output reports/tinfoil-realistic.json
```

Reports contain client and server timing rows, BER, raw and permutation-bias-corrected mutual information, a stratified permutation p-value, observed information, trial throughput, per-overlap results, reliable bits/hour, latency, utilization, runtime controls, profile, and artifact hashes. The benchmark averages all probes in a trial, calibrates each overlap offset separately, and uses a seeded balanced/randomized bit-by-offset schedule.

`raw_reliable_bits_per_hour` is diagnostic: short chance-level runs can have positive plug-in mutual information that becomes a large hourly extrapolation. The headline `reliable_bits_per_hour` is zero unless the corrected signal passes the permutation test (`p <= 0.05`). A result below 10 headline reliable bits/hour for a realistic profile is provisional evidence for that tested configuration—not proof of non-interference. Always compare signal runs with no-signal controls and multiple seeds.

See [the threat model](docs/threat-model.md), [research notes](docs/research-notes.md), and [Tinfoil deployment guide](docs/running-on-tinfoil.md).
