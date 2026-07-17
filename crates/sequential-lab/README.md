# Sequential chunk leakage lab

This research-only binary measures whether one globally serialized, fresh-process WASM invocation
can leave timing residue visible to the invocation that follows it. It is deliberately not a
dependency of `ishtar-scheduler`, and the production Dockerfile does not copy it.

The service has one authenticated turn route, one global execution permit, fixed-size parent-owned
state slots, and a fresh sandboxed child plus fresh Wasmi Store for every turn. The included client
runs balanced sender-to-probe pairs with an external clock and produces signal/control reports.

Build and start a raw-timing local lab:

```bash
export LAB_ADMIN_TOKEN='replace-with-at-least-16-bytes'
cargo build --release -p ishtar-sequential-lab

target/release/ishtar-sequential-lab serve \
  --bind 127.0.0.1:8081 \
  --execution-cutoff-us 100000 \
  --release-slot-us 0
```

Run matched signal and no-signal controls from another terminal:

```bash
target/release/ishtar-sequential-lab bench \
  --base-url http://127.0.0.1:8081 \
  --trials 1200 --seed 1 \
  --output reports/sequential/signal-seed-1.json

target/release/ishtar-sequential-lab bench \
  --base-url http://127.0.0.1:8081 \
  --trials 1200 --seed 1 --control \
  --output reports/sequential/control-seed-1.json
```

Then repeat with a padded service, for example `--execution-cutoff-us 8000
--release-slot-us 10000`. A nonzero release slot must reserve at least one millisecond for explicit
kill-and-reap cleanup.

The default added client-delay sweep is `0,50,250,1000,5000,20000` microseconds. The physical
sender-to-probe gap also includes the normalized sender response and the next request's proxy/network
turnaround; this deliberately measures the channel available to an external caller. Reports retain
every raw trial, per-gap latency distributions and calibrated BER, raw and
permutation-bias-corrected mutual information, a stratified permutation p-value, and detected
corrected bits/hour.

The client snapshots authenticated aggregate runner counters before and after the campaign and
rejects the run if any turn timed out or failed. Use a release build for measurements; debug Wasmi
compilation can exceed realistic cutoffs.

Local non-Linux runs exercise functionality but do not install Landlock or seccomp. Production-like
measurements require the Linux runner and the actual target hardware.
