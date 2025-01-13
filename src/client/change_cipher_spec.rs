use aes_gcm::aead::Buffer;

use crate::{
    handshake::{HandshakeType, TLSVersion},
    record_layer::ContentType,
};

#[derive(Debug)]
pub struct ChangeCipherSpec {
    tls_version: TLSVersion,
}

impl ChangeCipherSpec {
    pub fn new(tls_version: TLSVersion) -> ChangeCipherSpec {
        ChangeCipherSpec {
            tls_version: tls_version,
        }
    }

    pub fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice((1 as u8).to_be_bytes().as_ref());
        result
    }
}
