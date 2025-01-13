use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};
use sha2::{Digest, Sha256};

use crate::{generate_key::PRF, handshake::HandshakeType};

// https://docs.rs/aes-gcm/latest/aes_gcm/

fn encrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(key);

    let cipher = Aes256Gcm::new(&key);

    let message_length = (message.len() as u16).to_be_bytes();

    let mut associated_data = vec![];
    associated_data.extend_from_slice(&[0; 8]);
    associated_data.extend_from_slice(&[22 as u8]);
    associated_data.extend_from_slice(&[0x03, 0x03]);
    associated_data.extend_from_slice(message_length.as_ref());

    let payload = Payload {
        msg: message,
        aad: &associated_data,
    };

    let encrypted_message = cipher
        .encrypt(Nonce::from_slice(&[0; 12]), payload)
        .expect("encryption failure!");

    return encrypted_message;
}

struct FinishedMessage {
    verify_data: [u8; 12],
}

impl FinishedMessage {
    fn new(master_secret: &[u8; 48], handshake_messages: &[u8]) -> FinishedMessage {
        let verify_data = generate_verify_data(master_secret, handshake_messages);
        FinishedMessage {
            verify_data: verify_data
                .try_into()
                .expect("verify_data must be 12 bytes"),
        }
    }

    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(&[HandshakeType::Finished as u8]);
        result.extend_from_slice(&(self.verify_data.len() as u32).to_be_bytes()[1..4]);
        result.extend_from_slice(&self.verify_data);
        return result;
    }
}

fn generate_verify_data(master_secret: &[u8; 48], handshake_messages: &[u8]) -> Vec<u8> {
    let hashed_data = Sha256::digest(handshake_messages);
    let hashed_data_vec = hashed_data.to_vec();
    let verify_data = PRF(master_secret, &hashed_data_vec, "client finished", 12);
    return verify_data;
}
