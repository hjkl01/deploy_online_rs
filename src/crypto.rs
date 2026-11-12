//! Secret 加密：由 SECRET_KEY 派生密钥，XOR+HMAC 风格的简单对称封装
//! （单机工具够用；生产若有更高要求可换成 age / libsodium）

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};

const PREFIX: &str = "enc:v1:";

fn derive_key(secret_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"deploy_online.secret.v1");
    hasher.update(secret_key.as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // 简化 HMAC：ipad/opad
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

pub fn encrypt_secret(secret_key: &str, plaintext: &str) -> Result<String> {
    let key = derive_key(secret_key);
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let pt = plaintext.as_bytes();
    let mut ct = Vec::with_capacity(pt.len());
    // 密钥流：HMAC(key, nonce || counter)
    let mut counter = 0u64;
    let mut pos = 0usize;
    while pos < pt.len() {
        let mut block_input = Vec::with_capacity(24);
        block_input.extend_from_slice(&nonce);
        block_input.extend_from_slice(&counter.to_be_bytes());
        let stream = hmac_sha256(&key, &block_input);
        let n = (pt.len() - pos).min(32);
        for i in 0..n {
            ct.push(pt[pos + i] ^ stream[i]);
        }
        pos += n;
        counter += 1;
    }
    let mut mac_data = Vec::new();
    mac_data.extend_from_slice(&nonce);
    mac_data.extend_from_slice(&ct);
    let mac = hmac_sha256(&key, &mac_data);
    let mut packed = Vec::with_capacity(16 + 32 + ct.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&mac);
    packed.extend_from_slice(&ct);
    Ok(format!("{}{}", PREFIX, B64.encode(packed)))
}

pub fn decrypt_secret(secret_key: &str, value: &str) -> Result<String> {
    if !value.starts_with(PREFIX) {
        // 明文兼容（迁移期）
        return Ok(value.to_string());
    }
    let raw = B64
        .decode(value[PREFIX.len()..].as_bytes())
        .map_err(|e| anyhow::anyhow!("密文 base64 无效: {e}"))?;
    if raw.len() < 48 {
        bail!("密文过短");
    }
    let key = derive_key(secret_key);
    let nonce = &raw[..16];
    let mac = &raw[16..48];
    let ct = &raw[48..];
    let mut mac_data = Vec::new();
    mac_data.extend_from_slice(nonce);
    mac_data.extend_from_slice(ct);
    let expect = hmac_sha256(&key, &mac_data);
    if expect.as_slice() != mac {
        bail!("无法解密：SECRET_KEY 不匹配或数据损坏");
    }
    let mut pt = Vec::with_capacity(ct.len());
    let mut counter = 0u64;
    let mut pos = 0usize;
    while pos < ct.len() {
        let mut block_input = Vec::new();
        block_input.extend_from_slice(nonce);
        block_input.extend_from_slice(&counter.to_be_bytes());
        let stream = hmac_sha256(&key, &block_input);
        let n = (ct.len() - pos).min(32);
        for i in 0..n {
            pt.push(ct[pos + i] ^ stream[i]);
        }
        pos += n;
        counter += 1;
    }
    String::from_utf8(pt).map_err(|e| anyhow::anyhow!("明文非 UTF-8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = encrypt_secret("test-secret-key-32bytes!!!!!!!!", "hello-中文").unwrap();
        assert!(s.starts_with(PREFIX));
        assert_eq!(
            decrypt_secret("test-secret-key-32bytes!!!!!!!!", &s).unwrap(),
            "hello-中文"
        );
    }
}
