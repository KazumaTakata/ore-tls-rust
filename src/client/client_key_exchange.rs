use crate::handshake::HandshakeType;

#[derive(Debug)]
pub struct ClientKeyExchange {
    pub(crate) message: [u8; 32],
}

impl ClientKeyExchange {
    pub fn new(message: [u8; 32]) -> ClientKeyExchange {
        ClientKeyExchange { message: message }
    }

    pub fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        let message_length = ((self.message.len() + 1) as u32).to_be_bytes();
        result.extend_from_slice(&[HandshakeType::ClientKeyExchange as u8]);
        result.extend_from_slice(message_length[1..4].as_ref());
        result.extend_from_slice(&[32 as u8]);
        result.extend_from_slice(&self.message);
        result
    }
}
