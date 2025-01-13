use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes128Gcm, Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};

use crate::{encrypt, generate_key::PRF, handshake::HandshakeType, record_layer::ContentType};

// https://docs.rs/aes-gcm/latest/aes_gcm/

#[derive(Debug)]
pub struct FinishedMessage {
    verify_data: [u8; 12],
    key: [u8; 16],
    iv: Vec<u8>,
}

impl FinishedMessage {
    pub fn new(
        master_secret: &[u8; 48],
        handshake_messages: &[u8],
        key: &[u8; 16],
        iv: Vec<u8>,
    ) -> FinishedMessage {
        let verify_data = generate_verify_data(master_secret, handshake_messages);
        FinishedMessage {
            verify_data: verify_data
                .try_into()
                .expect("verify_data must be 12 bytes"),
            key: *key,
            iv: iv,
        }
    }

    pub fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(&[HandshakeType::Finished as u8]);
        let verified_data_length = (self.verify_data.len() as u32).to_be_bytes();
        result.extend_from_slice(&verified_data_length[1..4]);
        result.extend_from_slice(&self.verify_data);
        let encrypted_message =
            encrypt::encrypt_message(&self.key, &self.iv, &result, [0; 8], ContentType::Handshake);

        let mut result_2 = vec![];
        result_2.extend_from_slice(&[0; 8]);
        result_2.extend_from_slice(&encrypted_message);

        return result_2;
    }
}

fn generate_verify_data(master_secret: &[u8; 48], handshake_messages: &[u8]) -> Vec<u8> {
    let hashed_data = Sha256::digest(handshake_messages);
    let hashed_data_vec = hashed_data.to_vec();
    let verify_data = PRF(master_secret, &hashed_data_vec, "client finished", 12);
    return verify_data;
}
