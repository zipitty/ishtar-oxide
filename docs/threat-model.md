# Threat model

## Measured question

Can cooperating restricted-WASM turns in independent anonymous sessions communicate synthetic bits through CPU or memory contention, as observed through public HTTP completion timing? The external client owns the clock and chooses sender/probe overlap. Server records are administrative ground truth for analysis, not an observation available to an ordinary session.

## Attacker capabilities

The attacker can create many sessions, retain their bearer tokens, choose allowlisted profiles and synthetic sender bits, issue parallel turns, and measure end-to-end latency. The attacker knows all public source and benchmark WASM. Attacker-favorable profiles deliberately maximize overlap and lifetime; realistic profiles add unrelated sessions, jitter, fuel bounds, release epochs, and five-minute idle expiry.

Session identifiers are routing labels, not authorization. A 256-bit random bearer token authorizes one RAM-only session. Tokens are never logged or passed to WASM; the server stores only SHA-256 hashes and compares hashes in constant time.

## In scope

- scheduling, CPU-cache, memory-bandwidth, and allocator/process-start contention visible in HTTP timing;
- BER, false-positive/negative rates, binary mutual information, reliable bits/hour, overlap, latency, and utilization;
- explicit comparison of raw upper bounds, realistic profiles, and mandatory no-signal controls.

## Out of scope

- real prompts, secrets, model weights, production tenants, arbitrary module upload, native ELF, WASI, JITs, Spectre-class microarchitectural exploitation, host/enclave compromise, traffic analysis outside the endpoint, and denial of service;
- proving all covert channels absent. Measurements characterize only the named hardware, image, Tinfoil configuration, scheduler/WASM hashes, profile, client placement, and run.

## Statistical interpretation

The client uses a seeded balanced/randomized bit-by-overlap schedule so bit values are not confounded with cyclic overlap offsets. It reserves five examples of each bit at every offset for calibration, averages all successful probe latencies in a trial, fits a separate threshold and direction for each offset, and scores only held-out trials.

Raw plug-in mutual information is retained for auditability, but it is positively biased in finite samples. The report therefore permutes expected bits within overlap strata to estimate the chance baseline and p-value. `corrected_reliable_bits_per_hour` subtracts the mean permutation baseline; the headline `reliable_bits_per_hour` additionally requires `permutation_p_value <= 0.05`. `raw_information_bits_observed` and `corrected_information_bits_observed` show what the run itself measured, avoiding confusion between observed information and an hourly extrapolation.

The provisional realistic-profile concern threshold is 10 headline reliable bits/hour. It is a triage value, not a security proof or release gate by itself. A signal run must also be repeated across seeds and compared with its mandatory no-signal control; `p <= 0.05` is evidence against this benchmark's null model, not proof of exploitability.
