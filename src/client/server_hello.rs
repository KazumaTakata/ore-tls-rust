use crate::handshake::{CipherSuites, HandshakeExtension, TLSVersion};

pub struct ServerHello {
    version: TLSVersion,
    random: [u8; 32],
    cipher_suites: Vec<CipherSuites>,
    extensions: Vec<HandshakeExtension>,
}

impl ServerHello {
    pub fn from_byte_vector(data: Vec<u8>) -> ServerHello {
        let length_1 = data[1];
        let length_2 = data[2];
        let length_3 = data[3];

        let length = u32::from_be_bytes([0, length_1, length_2, length_3]);

        let server_hello_data = data[4..(4 + length as usize)].to_vec();

        let tls_version = u16::from_be_bytes([server_hello_data[0], server_hello_data[1]]);
        let parsed_tls_version = TLSVersion::from_u16(tls_version);
        let random = server_hello_data[2..34].to_vec();

        let session_id_length = server_hello_data[34];

        let cipher_suite = u16::from_be_bytes([server_hello_data[35], server_hello_data[36]]);
        let parsed_cipher_suit = CipherSuites::from_u16(cipher_suite);

        let compression_method = server_hello_data[37];

        let extension_length = u16::from_be_bytes([server_hello_data[38], server_hello_data[39]]);

        let server_extension = HandshakeExtension::from_byte_vector(
            data[40..(40 + extension_length as usize)].to_vec(),
        );

        return ServerHello {
            version: parsed_tls_version,
            random: random.try_into().unwrap(),
            cipher_suites: vec![parsed_cipher_suit],
            extensions: vec![server_extension],
        };
    }
}
