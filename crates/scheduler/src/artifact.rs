use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use std::{env, sync::Arc, time::Duration};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ISHTAR1\0";
const AUTHORIZED_HOST: &str = "artifacts.kkbr.ai";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = MAGIC.len() + NONCE_BYTES;

pub struct StartupSecrets {
    url: Zeroizing<String>,
    key: Zeroizing<Vec<u8>>,
    api_token: Zeroizing<String>,
}

pub struct LoadedArtifact {
    pub module: Arc<[u8]>,
    pub sha256_hex: String,
}

impl StartupSecrets {
    /// Takes both secrets out of the environment before the async runtime starts.
    pub fn take_from_environment() -> Result<Self> {
        let url = env::var("WASM_PULL_URL").context("WASM_PULL_URL secret is required")?;
        let encoded_key = Zeroizing::new(
            env::var("WASM_DECRYPTION_KEY").context("WASM_DECRYPTION_KEY secret is required")?,
        );
        let api_token = Zeroizing::new(
            env::var("WASM_PULL_API_TOKEN").context("WASM_PULL_API_TOKEN secret is required")?,
        );
        // SAFETY: this runs before the scheduler creates any threads.
        unsafe {
            env::remove_var("WASM_PULL_URL");
            env::remove_var("WASM_DECRYPTION_KEY");
            env::remove_var("WASM_PULL_API_TOKEN");
        }
        let parsed = reqwest::Url::parse(&url).map_err(|_| anyhow!("WASM_PULL_URL is invalid"))?;
        if parsed.scheme() != "https"
            || parsed.host_str() != Some(AUTHORIZED_HOST)
            || parsed.port_or_known_default() != Some(443)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            bail!("WASM_PULL_URL must be an HTTPS URL on {AUTHORIZED_HOST} port 443");
        }
        let key = Zeroizing::new(
            STANDARD
                .decode(encoded_key.as_bytes())
                .map_err(|_| anyhow!("WASM_DECRYPTION_KEY must be base64"))?,
        );
        if key.len() != 32 {
            bail!("WASM_DECRYPTION_KEY must decode to 32 bytes");
        }
        if api_token.is_empty() || api_token.len() > 4096 {
            bail!("WASM_PULL_API_TOKEN must contain 1..=4096 bytes");
        }
        Ok(Self {
            url: Zeroizing::new(url),
            key,
            api_token,
        })
    }
}

pub async fn pull_and_decrypt(
    secrets: StartupSecrets,
    max_module_bytes: usize,
) -> Result<LoadedArtifact> {
    let max_encrypted_bytes = max_module_bytes
        .checked_add(HEADER_BYTES + TAG_BYTES)
        .context("artifact size limit overflow")?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
        .map_err(|_| anyhow!("build artifact pull client"))?;
    let authorization = bearer_header(&secrets.api_token)?;
    let mut response = client
        .get(secrets.url.as_str())
        .header(reqwest::header::AUTHORIZATION, authorization)
        .send()
        .await
        .map_err(|_| anyhow!("artifact pull failed"))?
        .error_for_status()
        .map_err(|_| anyhow!("artifact source returned an error"))?;
    if response
        .content_length()
        .is_some_and(|length| length > max_encrypted_bytes as u64)
    {
        bail!("encrypted artifact exceeds policy");
    }
    let mut encrypted = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("artifact body read failed"))?
    {
        if encrypted.len().saturating_add(chunk.len()) > max_encrypted_bytes {
            bail!("encrypted artifact exceeds policy");
        }
        encrypted.extend_from_slice(&chunk);
    }
    decrypt(&encrypted, &secrets.key, max_module_bytes)
}

fn bearer_header(token: &str) -> Result<reqwest::header::HeaderValue> {
    let value = Zeroizing::new(format!("Bearer {token}"));
    let mut header = reqwest::header::HeaderValue::from_str(&value)
        .map_err(|_| anyhow!("WASM_PULL_API_TOKEN is not a valid HTTP bearer token"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn decrypt(encrypted: &[u8], key_bytes: &[u8], max_module_bytes: usize) -> Result<LoadedArtifact> {
    if encrypted.len() <= HEADER_BYTES + TAG_BYTES || &encrypted[..MAGIC.len()] != MAGIC {
        bail!("invalid encrypted artifact envelope");
    }
    let nonce = Nonce::try_assume_unique_for_key(&encrypted[MAGIC.len()..HEADER_BYTES])
        .map_err(|_| anyhow!("invalid artifact nonce"))?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| anyhow!("invalid artifact decryption key"))?,
    );
    let mut in_out = Zeroizing::new(encrypted[HEADER_BYTES..].to_vec());
    let plaintext = key
        .open_in_place(nonce, Aad::from(MAGIC), &mut in_out)
        .map_err(|_| anyhow!("artifact authentication failed"))?;
    if plaintext.is_empty() || plaintext.len() > max_module_bytes {
        bail!("decrypted module size violates policy");
    }
    let sha256_hex = hex::encode(Sha256::digest(&*plaintext));
    Ok(LoadedArtifact {
        module: Arc::from(&*plaintext),
        sha256_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::aead;

    fn envelope(plaintext: &[u8], key_bytes: &[u8]) -> Vec<u8> {
        let nonce_bytes = [7; NONCE_BYTES];
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key_bytes).unwrap());
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(MAGIC), &mut ciphertext)
            .unwrap();
        [MAGIC.as_slice(), &nonce_bytes, &ciphertext].concat()
    }

    #[test]
    fn decrypts_authenticated_envelope_and_hashes_plaintext() {
        let key = [3; 32];
        let loaded = decrypt(&envelope(b"wasm", &key), &key, 16).unwrap();
        assert_eq!(&*loaded.module, b"wasm");
        assert_eq!(loaded.sha256_hex, hex::encode(Sha256::digest(b"wasm")));
    }

    #[test]
    fn rejects_tampering_wrong_keys_and_oversized_plaintext() {
        let key = [3; 32];
        let mut encrypted = envelope(b"wasm", &key);
        *encrypted.last_mut().unwrap() ^= 1;
        assert!(decrypt(&encrypted, &key, 16).is_err());
        assert!(decrypt(&envelope(b"wasm", &key), &[4; 32], 16).is_err());
        assert!(decrypt(&envelope(b"wasm", &key), &key, 3).is_err());
    }

    #[test]
    fn envelope_overhead_is_stable() {
        assert_eq!(aead::MAX_TAG_LEN, TAG_BYTES);
        assert_eq!(envelope(b"x", &[3; 32]).len(), HEADER_BYTES + TAG_BYTES + 1);
    }

    #[test]
    fn authorized_source_is_exact_not_a_suffix_match() {
        for allowed in [
            "https://artifacts.kkbr.ai/worker.enc",
            "https://artifacts.kkbr.ai:443/signed?token=secret",
        ] {
            let url = reqwest::Url::parse(allowed).unwrap();
            assert_eq!(url.host_str(), Some(AUTHORIZED_HOST));
            assert_eq!(url.port_or_known_default(), Some(443));
        }
        for denied in [
            "https://evil-artifacts.kkbr.ai/worker.enc",
            "https://artifacts.kkbr.ai.evil.test/worker.enc",
            "https://artifacts.kkbr.ai@evil.test/worker.enc",
            "http://artifacts.kkbr.ai/worker.enc",
        ] {
            let url = reqwest::Url::parse(denied).unwrap();
            assert!(url.scheme() != "https" || url.host_str() != Some(AUTHORIZED_HOST));
        }
    }

    #[test]
    fn bearer_header_is_sensitive_and_rejects_header_injection() {
        let header = bearer_header("secret-token").unwrap();
        assert_eq!(header, "Bearer secret-token");
        assert!(header.is_sensitive());
        assert!(bearer_header("secret\r\ninjected: value").is_err());
    }
}
