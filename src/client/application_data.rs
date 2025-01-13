use crate::{encrypt, record_layer::ContentType};

#[derive(Debug)]
pub struct ApplicationData {
    data: Vec<u8>,
    key: [u8; 16],
    iv: Vec<u8>,
}

impl ApplicationData {
    pub fn new(data: Vec<u8>, key: &[u8; 16], iv: Vec<u8>) -> ApplicationData {
        ApplicationData {
            data,
            key: *key,
            iv: iv,
        }
    }

    pub fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];

        let explicit_nonce = (1 as u64).to_be_bytes();
        let encrypted_data = encrypt::encrypt_message(
            &self.key,
            &self.iv,
            &self.data,
            explicit_nonce,
            ContentType::ApplicationData,
        );

        result.extend_from_slice(&explicit_nonce);
        result.extend_from_slice(&encrypted_data);

        return result;
    }
}
