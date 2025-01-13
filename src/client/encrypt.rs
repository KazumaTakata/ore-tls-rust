use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes128Gcm, Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};

use crate::{generate_key::PRF, handshake::HandshakeType, record_layer::ContentType};

// https://docs.rs/aes-gcm/latest/aes_gcm/

pub fn encrypt_message(
    key: &[u8; 16],
    iv: &Vec<u8>,
    message: &[u8],
    explicit_iv: [u8; 8],
    content_type: ContentType,
) -> Vec<u8> {
    let key = Key::<Aes128Gcm>::from_slice(key);

    let cipher = Aes128Gcm::new(&key);

    let message_length = (message.len() as u16).to_be_bytes();

    let mut associated_data = vec![];
    associated_data.extend_from_slice(&explicit_iv);
    associated_data.extend_from_slice(&[content_type as u8]);
    associated_data.extend_from_slice(&[0x03, 0x03]);
    associated_data.extend_from_slice(message_length.as_ref());

    let payload = Payload {
        msg: message,
        aad: &associated_data,
    };

    let mut nonce_vector = vec![];
    nonce_vector.extend_from_slice(&iv);
    nonce_vector.extend_from_slice(&explicit_iv);

    let nonce = Nonce::from_slice(&nonce_vector);
    let encrypted_message = cipher.encrypt(nonce, payload).expect("encryption failure!");

    return encrypted_message;
}
