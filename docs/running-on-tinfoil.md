# Running on Tinfoil

These instructions follow Tinfoil's public-container template and container documentation as retrieved on 2026-07-11. The workflow actions are pinned to the same commits as the official template.

## One-time repository setup

1. The repository must be public for the public-container flow.
2. The config is prepared for `zipitty/ishtar-oxide`. If the eventual public repository differs, change `ghcr.io/zipitty/ishtar-oxide:placeholder` before the first release. Leave `:placeholder`; the release workflow replaces it with the built image's immutable digest in the release tag.
3. Install the Tinfoil GitHub App for the repository and ensure GitHub Actions can create pull requests.
4. In Tinfoil Dashboard → Containers → Secrets, create `LAB_ADMIN_TOKEN` with a high-entropy value of at least 16 bytes. Alternatively, after `tinfoil login`:

   ```bash
   printf '%s' "$LAB_ADMIN_TOKEN" | \
     tinfoil repo secret create zipitty/ishtar-oxide LAB_ADMIN_TOKEN --value-file -
   ```

Never commit or pass that value on a command line.

## What the attested config enforces

- CVM `0.10.8`, 8 CPUs, and 8192 MB RAM—the current official template value and valid resource sizes at implementation time.
- No `networks` block, which is Tinfoil's documented no-egress default. The shim-to-scheduler private channel is automatic.
- A read-only root, no capabilities, and no-new-privileges. The latter two are immutable Tinfoil runtime defaults.
- Numeric non-root user `65532:65532`, a 256-process limit, restart-on-failure, and an in-binary healthcheck.
- Each guest turn runs in a fresh single-threaded process with no-new-privileges, rlimits, and a kill-by-default seccomp filter. The image build executes a real control turn through that filter and fails if installation or execution fails.
- Only `/health` and `/v1/*` are exposed through the shim on port 8080.
- `/tinfoil/config.yml` and `/tinfoil/attestation.json` are hashed by the scheduler and included in run attribution, together with the source commit embedded by the image build.

## Release and attest

After merging the desired source/config state, trigger the official two-phase flow:

```bash
gh workflow run tinfoil-release.yml -f version=v0.1.0
```

Phase 1 builds and pushes `ghcr.io/zipitty/ishtar-oxide`, rewrites the config to its immutable `@sha256:...` reference in a release commit/tag, then dispatches phase 2. Phase 2 measures the image and publishes its keyless attestation and GitHub release. Both workflows must finish successfully before deployment.

The equivalent Tinfoil CLI command is:

```bash
tinfoil repo build run zipitty/ishtar-oxide --version v0.1.0
```

## Deploy production mode

Do not use debug mode: Tinfoil documents that debug containers cannot pass attestation.

```bash
tinfoil container create ishtar-oxide-lab \
  --repo zipitty/ishtar-oxide \
  --tag v0.1.0 \
  --secret LAB_ADMIN_TOKEN

tinfoil container get ishtar-oxide-lab
```

Wait for `Running`. The healthcheck verifies the packaged scheduler can load its profiles/WASM and answer `/health`.

## Run benchmarks locally against the enclave

Start the Tinfoil verified proxy in terminal 1. It verifies the release measurement and pins the enclave TLS certificate before forwarding traffic:

```bash
tinfoil container connect ishtar-oxide-lab --port 3301
```

In terminal 2, build only the external client and point it at the proxy:

```bash
cargo build --release -p ishtar-bench-client
export LAB_ADMIN_TOKEN='value-stored-in-tinfoil'

target/release/ishtar-bench-client profiles \
  --base-url http://127.0.0.1:3301

target/release/ishtar-bench-client run \
  --base-url http://127.0.0.1:3301 \
  --profile attacker-favorable --seed 7 \
  --output reports/tinfoil-attacker-favorable-seed-7.json

target/release/ishtar-bench-client run \
  --base-url http://127.0.0.1:3301 \
  --profile realistic --seed 7 \
  --output reports/tinfoil-realistic-seed-7.json

target/release/ishtar-bench-client run \
  --base-url http://127.0.0.1:3301 \
  --profile realistic --seed 7 --control \
  --output reports/tinfoil-realistic-control-seed-7.json
```

Repeat realistic and control runs with multiple seeds. Preserve the GitHub release/attestation URL with each report. Client timing includes the verified proxy path, which is intentional because the attacker observes end-to-end public HTTP behavior.

Interpret `reliable_bits_per_hour` as the headline only when `statistically_detected` is true, and inspect `corrected_information_bits_observed` to see how much information was actually measured during the finite run. `raw_reliable_bits_per_hour` is intentionally included to diagnose finite-sample inflation, not as a leakage claim. Compare `offset_summaries` to determine whether leakage is confined to particular overlap windows, and require signal/control separation across multiple seeds before drawing a conclusion.

Sources: [configuration](https://docs.tinfoil.sh/containers/configuration), [networking](https://docs.tinfoil.sh/containers/config-networking), [runtime security](https://docs.tinfoil.sh/containers/config-runtime), [connecting](https://docs.tinfoil.sh/containers/connecting), and [CLI lifecycle](https://docs.tinfoil.sh/containers/cli).
