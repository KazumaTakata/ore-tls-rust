use crate::handshake::{
    ApplicationLayerProtocol, ApplicationLayerProtocolNegotiationExtension, CipherSuites,
    ClientHelloExtensionType, HandshakeExtension, HandshakeProtocol, HandshakeType,
    SignatureAlgorithms, SignatureAlgorithmsExtension, SupportedGroupsExtension,
    SupportedVersionsExtension, TLSVersion,
};
use crate::server_hello::ServerHello;
use rand::rngs::OsRng;
use rand::RngCore;
use std::f32::consts::E;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;
use std::{io::Write, net::TcpStream, time::Duration};

#[derive(Debug)]
pub struct ClientHello {
    version: TLSVersion,
    random: [u8; 32],
    pub session_id: [u8; 32],
    cipher_suites: Vec<CipherSuites>,
    compression_methods: Vec<u8>,
    extensions: Vec<HandshakeExtension>,
}

impl ClientHello {
    pub fn new() -> ClientHello {
        ClientHello {
            version: TLSVersion::V1_2,
            random: ClientHello::generate_client_random(),
            session_id: ClientHello::generate_session_id().try_into().unwrap(),
            cipher_suites: vec![
                // TLS 1.3 Cipher Suites
                CipherSuites::TLS_AES_128_GCM_SHA256,
                CipherSuites::TLS_AES_256_GCM_SHA384,
                CipherSuites::TLS_CHACHA20_POLY1305_SHA256,
                // RSA Cipher Suites
                CipherSuites::TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuites::TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA256,
                CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA256,
                CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA,
                // ECDHE-ECDSA Cipher Suites
                CipherSuites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                // // ECDHE-RSA Cipher Suites
                CipherSuites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                // CipherSuites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                // CipherSuites::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                // CipherSuites::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                // CipherSuites::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                // // DHE-RSA Cipher Suites
                // CipherSuites::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                // CipherSuites::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                // CipherSuites::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],

            compression_methods: vec![0],
            extensions: vec![
                HandshakeExtension::SupportedVersions(SupportedVersionsExtension {
                    versions: vec![TLSVersion::V1_2],
                }),
                HandshakeExtension::SignatureAlgorithms(SignatureAlgorithmsExtension {
                    algorithms: vec![
                        SignatureAlgorithms::RSA_PKCS1_SHA256,
                        SignatureAlgorithms::RSA_PKCS1_SHA384,
                        SignatureAlgorithms::RSA_PKCS1_SHA512,
                        SignatureAlgorithms::ECDSA_SHA256,
                        SignatureAlgorithms::ECDSA_SHA384,
                        SignatureAlgorithms::ECDSA_SHA512,
                        SignatureAlgorithms::RSA_PSS_RSAE_SHA256,
                        SignatureAlgorithms::RSA_PSS_RSAE_SHA384,
                        SignatureAlgorithms::RSA_PSS_RSAE_SHA512,
                    ],
                }),
                HandshakeExtension::ApplicationLayerProtocolNegotiation(
                    ApplicationLayerProtocolNegotiationExtension {
                        algorithms: vec![ApplicationLayerProtocol::HTTP1_1],
                    },
                ),
                HandshakeExtension::SupportedGroups(SupportedGroupsExtension {
                    groups: vec![
                        SupportedGroups::X25519 as u16,
                        SupportedGroups::secp256r1 as u16,
                        SupportedGroups::secp384r1 as u16,
                        SupportedGroups::secp521r1 as u16,
                    ],
                }),
            ],
        }
    }
    fn generate_session_id() -> Vec<u8> {
        let mut session_id = vec![0u8; 32]; // 32バイトの最大長を使用
        OsRng.fill_bytes(&mut session_id);
        session_id
    }

    fn generate_client_random() -> [u8; 32] {
        let mut random = [0u8; 32];

        // 時刻またはランダム値を最初の4バイトに設定
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        random[0..4].copy_from_slice(&now.to_be_bytes());

        // 残りの28バイトをランダムに生成
        OsRng.fill_bytes(&mut random[4..]);

        random
    }
    pub fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.push(HandshakeType::ClientHello as u8);
        let mut client_hello_body = vec![];

        client_hello_body.extend_from_slice(&(self.version as u16).to_be_bytes());
        client_hello_body.extend_from_slice(&self.random);
        client_hello_body.push(self.session_id.len() as u8);
        client_hello_body.extend_from_slice(&self.session_id);
        client_hello_body.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for cipher_suite in &self.cipher_suites {
            client_hello_body.extend_from_slice(&((*cipher_suite) as u16).to_be_bytes());
        }
        client_hello_body.push(self.compression_methods.len() as u8);
        client_hello_body.extend_from_slice(&self.compression_methods);

        let mut client_hello_extension = vec![];

        for extension in &self.extensions {
            match extension {
                HandshakeExtension::SupportedVersions(supported_versions) => {
                    client_hello_extension.extend_from_slice(&supported_versions.to_byte_vector());
                }
                HandshakeExtension::SignatureAlgorithms(signature_algorithms) => {
                    client_hello_extension
                        .extend_from_slice(&signature_algorithms.to_byte_vector());
                }
                HandshakeExtension::ApplicationLayerProtocolNegotiation(alpn) => {
                    client_hello_extension.extend_from_slice(&alpn.to_byte_vector());
                }
                HandshakeExtension::SupportedGroups(supported_groups) => {
                    client_hello_extension.extend_from_slice(&supported_groups.to_byte_vector());
                }
            }
        }

        client_hello_body.extend_from_slice(&(client_hello_extension.len() as u16).to_be_bytes());
        client_hello_body.extend_from_slice(&client_hello_extension);

        let body_length = client_hello_body.len() as u32;

        let bytes: [u8; 3] = [
            ((body_length >> 16) & 0xFF) as u8,
            ((body_length >> 8) & 0xFF) as u8,
            (body_length & 0xFF) as u8,
        ];

        result.extend_from_slice(bytes.as_ref());
        result.extend_from_slice(&client_hello_body);

        result
    }
}

#[derive(Debug)]
pub struct RecordLayer<'a> {
    content_type: ContentType,
    version: TLSVersion,
    message: HandshakeProtocol<'a>,
}

impl<'a> RecordLayer<'a> {
    pub fn new<'b>() -> RecordLayer<'b> {
        let message = HandshakeProtocol::ClientHello(ClientHello::new());

        RecordLayer {
            content_type: ContentType::Handshake,
            version: TLSVersion::V1_2,
            message: message,
        }
    }

    pub fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.push(self.content_type as u8);
        result.extend_from_slice(&(self.version as u16).to_be_bytes());
        let message = self.message.to_byte_vector();
        result.extend_from_slice(&(message.len() as u16).to_be_bytes());
        result.extend_from_slice(&message);
        result
    }

    pub fn from_byte_vector(data: &'a [u8]) -> (RecordLayer<'a>, &'a [u8]) {
        let content_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = data[3];
        let length_2 = data[4];

        let parsed_length = u16::from_be_bytes([length, length_2]);

        let message = &data[5..(5 + parsed_length as usize)];
        let rest_message = &data[(5 + parsed_length as usize)..];
        let handshake_protocol = HandshakeProtocol::from_byte_vector(&message);
        return (
            RecordLayer {
                content_type: ContentType::Handshake,
                version: TLSVersion::from_u16(version),
                message: handshake_protocol,
            },
            rest_message,
        );
    }
}

#[derive(Copy, Clone, Debug)]
enum ContentType {
    ApplicationData,
    Handshake = 22,
    Alert,
    ChangeCipherSpec,
    Heartbeat,
}

enum SupportedGroups {
    X25519 = 0x001d,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    secp256k1 = 0x0016,
}
