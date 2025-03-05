use base64::prelude::*;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use chrono::prelude::*;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("Invalid {0}")]
    Invalid(String),

    #[error("Base64 {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Utf8 {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Chacha20 {0}")]
    Chacha20(#[from] chacha20poly1305::Error),
}

// 暗号化とBase64エンコード
pub fn encrypt_with_base64(key: &str, data: &str) -> Result<String, EncryptError> {
    let res = encrypt(key.as_bytes(), data.as_bytes())?;
    Ok(BASE64_STANDARD.encode(res))
}

// 復号化とBase64デコード。NonceがUUIDv7なので、UUIDも返す
pub fn decrypt_with_base64(key: &str, data: &str) -> Result<(String, Uuid), EncryptError> {
    let data = BASE64_STANDARD.decode(data)?;
    let uuid = get_uuid(&data)?;
    let plaintext = decrypt(key.as_bytes(), &data)?;
    String::from_utf8(plaintext.to_vec())
        .map_err(|e| e.into())
        .map(|s| (s, uuid))
}

// UUID取得
pub fn get_uuid(data: &[u8]) -> Result<Uuid, EncryptError> {
    let uuid_src = data[0..16]
        .to_vec()
        .try_into()
        .map_err(|_| EncryptError::Invalid("size invalid".to_string()))?;
    Ok(Uuid::from_bytes(uuid_src))
}

// Nonce生成。先頭16byteはUUID、残り8byteは乱数
pub fn make_nonce() -> Vec<u8> {
    let uuid = Uuid::now_v7();
    let mut res = uuid.as_bytes().to_vec();
    let mut rng = rand::rngs::StdRng::from_os_rng();
    res.extend(rng.random::<[u8; 8]>().to_vec());
    res
}

// 暗号化
pub fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    //let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 192-bits; unique per message
    let nonce_src = make_nonce();
    let nonce = XNonce::from_slice(&nonce_src);
    let ciphertext = cipher.encrypt(nonce, data)?;
    let mut res = nonce.to_vec();
    res.extend(ciphertext);
    Ok(res)
}

// 復号化
pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, EncryptError> {
    let nonce = &data[0..24];
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher.decrypt(nonce.into(), &data[24..])?;
    Ok(plaintext.to_vec())
}

// UUIDからUTCを取得
pub fn get_utc(uuid: &Uuid) -> Option<DateTime<Utc>> {
    if let Some(timestamp) = uuid.get_timestamp() {
        let (secs, nsecs) = timestamp.to_unix();
        Utc.timestamp_opt(secs as i64, nsecs).single()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RUST_LOG=info REALM_CODE=test cargo test -p common test_common_encript_chacha20 -- --nocapture --test-threads=1
    #[tokio::test]
    async fn test_common_encript_chacha20() -> anyhow::Result<()> {
        let plaintext = "予定表～①💖ﾊﾝｶｸだ";
        let key = "01234567890123456789012345678901"; // 32byte
        let enc = encrypt_with_base64(key, plaintext)?;
        let dec = decrypt_with_base64(key, &enc)?;
        assert_eq!(plaintext, dec.0);
        println!("{}\n{}\n{:?}", enc, dec.0, get_utc(&dec.1));
        Ok(())
    }
}