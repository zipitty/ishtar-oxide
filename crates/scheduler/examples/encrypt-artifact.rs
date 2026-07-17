use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use std::{env, fs, path::PathBuf};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ISHTAR1\0";

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let input = PathBuf::from(args.next().context("input WASM path is required")?);
    let output = PathBuf::from(args.next().context("output artifact path is required")?);
    if args.next().is_some() {
        bail!("usage: encrypt-artifact <input.wasm> <output.enc>");
    }
    let encoded_key =
        Zeroizing::new(env::var("WASM_DECRYPTION_KEY").context("WASM_DECRYPTION_KEY is required")?);
    let key_bytes = Zeroizing::new(
        STANDARD
            .decode(encoded_key.as_bytes())
            .map_err(|_| anyhow!("WASM_DECRYPTION_KEY must be base64"))?,
    );
    if key_bytes.len() != 32 {
        bail!("WASM_DECRYPTION_KEY must decode to 32 bytes");
    }
    let mut nonce_bytes = [0; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|_| anyhow!("OS randomness unavailable"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| anyhow!("invalid encryption key"))?,
    );
    let mut ciphertext = Zeroizing::new(fs::read(&input).context("read input WASM")?);
    key.seal_in_place_append_tag(nonce, Aad::from(MAGIC), &mut *ciphertext)
        .map_err(|_| anyhow!("encrypt WASM"))?;
    let mut envelope = Vec::with_capacity(MAGIC.len() + nonce_bytes.len() + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    fs::write(&output, envelope).context("write encrypted artifact")?;
    Ok(())
}
