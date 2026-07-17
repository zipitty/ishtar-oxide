# Running on Tinfoil

The checked-in `tinfoil-config.yml` deploys one read-only scheduler container. No module is packaged
in its image and there is no upload endpoint. At startup it pulls exactly one encrypted artifact from
a secret HTTPS URL, decrypts it in memory, and refuses to serve if the pull or authentication fails.

## Prepare the artifact

Generate a 256-bit key once and keep its base64 form:

```bash
export WASM_DECRYPTION_KEY="$(openssl rand -base64 32 | tr -d '\n')"
```

Encrypt a core WASM module that exports `run: () -> ()`:

```bash
cargo run -p ishtar-scheduler --example encrypt-artifact -- \
  worker.wasm worker.enc
```

The envelope is `ISHTAR1\0 || 12-byte random nonce || AES-256-GCM ciphertext || 16-byte tag`.
`ISHTAR1\0` is authenticated as associated data. Never reuse an artifact nonce with the same key;
the packaging utility obtains a fresh nonce from the operating system.

Place `worker.enc` at an HTTPS URL. Redirects are not followed. The scheduler streams at most the
compiled module limit plus envelope overhead, so the source need not send `Content-Length`.

## Configure secrets

Create all three Tinfoil secrets without putting their values in the image or attested YAML:

```bash
printf '%s' 'https://artifacts.kkbr.ai/worker.enc' | \
  tinfoil repo secret create zipitty/ishtar-oxide WASM_PULL_URL --value-file -

printf '%s' "$WASM_DECRYPTION_KEY" | \
  tinfoil repo secret create zipitty/ishtar-oxide WASM_DECRYPTION_KEY --value-file -

printf '%s' "$WASM_PULL_API_TOKEN" | \
  tinfoil repo secret create zipitty/ishtar-oxide WASM_PULL_API_TOKEN --value-file -
```

The URL may include a signed query. The scheduler sends `WASM_PULL_API_TOKEN` as an
`Authorization: Bearer ...` header and marks it sensitive. Redirects are disabled, so it is never
forwarded to another host. The scheduler removes all three variables from its environment before
creating runtime threads. Secret buffers and downloaded plaintext staging buffers are zeroized when
released; only the worker bytes and SHA-256 remain in memory.

The checked-in `artifact-pull` network allows egress only to `artifacts.kkbr.ai`. The scheduler also
requires the secret URL to use that exact hostname over HTTPS port 443; suffix lookalikes, embedded
credentials, other ports, and redirects are rejected. It performs one GET before binding its
listener and never derives a request from worker data. Sandboxed runners have no network syscall.

## Deploy and verify

Publish and deploy with the pinned release workflows. Startup remains unhealthy until the artifact
has been fetched and decrypted. Then start an attestation-verifying local proxy:

```bash
tinfoil container connect YOUR_CONTAINER_NAME --port 3301
```

Inspect the loaded plaintext hash:

```bash
curl --fail http://127.0.0.1:3301/health
```

Invoke the fixed worker with an empty request body:

```bash
curl --fail -X POST http://127.0.0.1:3301/v1/run
```

Every admitted request returns `{"outcome":"complete"}` at its fixed slot deadline. That response
does not say whether the module ran successfully, trapped, exhausted fuel, or was killed.
