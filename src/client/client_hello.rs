use rand::rngs::OsRng;
use rand::RngCore;
use std::f32::consts::E;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;
use std::{io::Write, net::TcpStream, time::Duration};

pub enum HandshakeProtocol {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
}

impl HandshakeProtocol {
    fn to_byte_vector(&self) -> Vec<u8> {
        match self {
            HandshakeProtocol::ClientHello(client_hello) => client_hello.to_byte_vector(),
            _ => vec![],
        }
    }

    fn from_byte_vector(data: Vec<u8>) -> HandshakeProtocol {
        let handshake_type = HandshakeType::try_from(data[0]).unwrap();
        match handshake_type {
            HandshakeType::ServerHello => {
                let server_hello = ServerHello::from_byte_vector(data);
                HandshakeProtocol::ServerHello(server_hello)
            }
            _ => panic!("Unsupported handshake type"),
        }
    }
}

pub struct ServerHello {
    version: TLSVersion,
    random: [u8; 32],
    cipher_suites: Vec<CipherSuites>,
    extensions: Vec<HandshakeExtension>,
}

impl ServerHello {
    fn from_byte_vector(data: Vec<u8>) -> ServerHello {
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

pub struct ClientHello {
    version: TLSVersion,
    random: [u8; 32],
    session_id: [u8; 32],
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
    fn to_byte_vector(&self) -> Vec<u8> {
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

pub struct RecordLayer {
    content_type: ContentType,
    version: TLSVersion,
    message: HandshakeProtocol,
}

impl RecordLayer {
    pub fn new() -> RecordLayer {
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

    pub fn from_byte_vector(data: Vec<u8>) -> RecordLayer {
        let content_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = data[3];
        let length_2 = data[4];

        let parsed_length = u16::from_be_bytes([length, length_2]);

        let message = data[5..(5 + parsed_length as usize)].to_vec();
        let handshake_protocol = HandshakeProtocol::from_byte_vector(message);
        RecordLayer {
            content_type: ContentType::Handshake,
            version: TLSVersion::from_u16(version),
            message: handshake_protocol,
        }
    }
}

#[derive(Copy, Clone)]
enum ContentType {
    ApplicationData,
    Handshake = 22,
    Alert,
    ChangeCipherSpec,
    Heartbeat,
}

#[derive(Copy, Clone)]
enum TLSVersion {
    V1_0 = 0x0301,
    V1_1 = 0x0302,
    V1_2 = 0x0303,
    V1_3 = 0x0304,
}

impl TLSVersion {
    fn from_u16(value: u16) -> TLSVersion {
        match value {
            0x0301 => TLSVersion::V1_0,
            0x0302 => TLSVersion::V1_1,
            0x0303 => TLSVersion::V1_2,
            0x0304 => TLSVersion::V1_3,
            _ => TLSVersion::V1_2,
        }
    }
}

#[derive(Copy, Clone)]
enum CipherSuites {
    // TLS 1.3 Cipher Suites
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,

    // TLS 1.2 RSA Cipher Suites
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c,
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,

    // ECDSA Cipher Suites
    TLS_ED25519_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0x0807,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,

    // ECDHE-RSA Cipher Suites
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028,

    // DHE Cipher Suites
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,
}

impl CipherSuites {
    fn from_u16(value: u16) -> CipherSuites {
        match value {
            0x1301 => CipherSuites::TLS_AES_128_GCM_SHA256,
            0x1302 => CipherSuites::TLS_AES_256_GCM_SHA384,
            0x1303 => CipherSuites::TLS_CHACHA20_POLY1305_SHA256,
            0x009c => CipherSuites::TLS_RSA_WITH_AES_128_GCM_SHA256,
            0x009d => CipherSuites::TLS_RSA_WITH_AES_256_GCM_SHA384,
            0x003c => CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA256,
            0x003d => CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA256,
            0x002f => CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA,
            0x0035 => CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA,
            0x0807 => CipherSuites::TLS_ED25519_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            0xc02b => CipherSuites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            0xc02c => CipherSuites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            0xcca9 => CipherSuites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            0xc02f => CipherSuites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            0xc030 => CipherSuites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            0xcca8 => CipherSuites::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            0xc027 => CipherSuites::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            0xc028 => CipherSuites::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            0x009e => CipherSuites::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            0x009f => CipherSuites::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            0xccaa => CipherSuites::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            _ => CipherSuites::TLS_RSA_WITH_AES_128_GCM_SHA256,
        }
    }
}

#[derive(Copy, Clone)]
enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateURL = 21,
    CertificateStatus = 22,
    SupplementalData = 23,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl TryFrom<u8> for HandshakeType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HandshakeType::HelloRequest),
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            3 => Ok(HandshakeType::HelloVerifyRequest),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            21 => Ok(HandshakeType::CertificateURL),
            22 => Ok(HandshakeType::CertificateStatus),
            23 => Ok(HandshakeType::SupplementalData),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(()),
        }
    }
}

enum ClientHelloExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSRTP = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
}

struct SupportedVersionsExtension {
    versions: Vec<TLSVersion>,
}

impl SupportedVersionsExtension {
    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result
            .extend_from_slice(&(ClientHelloExtensionType::SupportedVersions as u16).to_be_bytes());
        result.extend_from_slice(&((self.versions.len() * 2 + 1) as u16).to_be_bytes());
        result.extend_from_slice(&((self.versions.len() * 2) as u8).to_be_bytes());
        for version in &self.versions {
            result.extend_from_slice(&((*version) as u16).to_be_bytes());
        }
        result
    }
}

enum HandshakeExtension {
    SupportedVersions(SupportedVersionsExtension),
    SignatureAlgorithms(SignatureAlgorithmsExtension),
    ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiationExtension),
    SupportedGroups(SupportedGroupsExtension),
}

impl HandshakeExtension {
    fn from_byte_vector(data: Vec<u8>) -> HandshakeExtension {
        let extension_type = u16::from_be_bytes([data[0], data[1]]);
        let extension_length = u16::from_be_bytes([data[2], data[3]]);
        let extension_data = data[4..(4 + extension_length as usize)].to_vec();
        match extension_type {
            16 => HandshakeExtension::ApplicationLayerProtocolNegotiation(
                ApplicationLayerProtocolNegotiationExtension::from_byte_vector(extension_data),
            ),
            _ => HandshakeExtension::ApplicationLayerProtocolNegotiation(
                ApplicationLayerProtocolNegotiationExtension::from_byte_vector(extension_data),
            ),
        }
    }
}

struct SignatureAlgorithmsExtension {
    algorithms: Vec<SignatureAlgorithms>,
}

struct SupportedGroupsExtension {
    groups: Vec<u16>,
}

impl SupportedGroupsExtension {
    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(&(ClientHelloExtensionType::SupportedGroups as u16).to_be_bytes());
        result.extend_from_slice(&((self.groups.len() * 2 + 2) as u16).to_be_bytes());
        result.extend_from_slice(&((self.groups.len() * 2) as u16).to_be_bytes());
        for group in &self.groups {
            result.extend_from_slice(&(*group as u16).to_be_bytes());
        }
        result
    }
}

enum SupportedGroups {
    X25519 = 0x001d,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    secp256k1 = 0x0016,
}

struct ApplicationLayerProtocolNegotiationExtension {
    algorithms: Vec<ApplicationLayerProtocol>,
}

impl ApplicationLayerProtocolNegotiationExtension {
    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(
            &(ClientHelloExtensionType::ApplicationLayerProtocolNegotiation as u16).to_be_bytes(),
        );

        let mut algorithm_result = vec![];

        for protocol in &self.algorithms {
            algorithm_result.extend_from_slice(&protocol.to_byte_vector());
        }

        result.extend_from_slice(&((algorithm_result.len() + 2) as u16).to_be_bytes());
        result.extend_from_slice(&((algorithm_result.len()) as u16).to_be_bytes());
        result.extend_from_slice(&algorithm_result);

        result
    }
    fn from_byte_vector(data: Vec<u8>) -> ApplicationLayerProtocolNegotiationExtension {
        let _length = u16::from_be_bytes([data[0], data[1]]);
        let alpn_extension_length = u16::from_be_bytes([data[2], data[3]]);
        let protocol = data[2..(2 + alpn_extension_length as usize)].to_vec();
        match protocol.as_slice() {
            b"http/1.1" => ApplicationLayerProtocolNegotiationExtension {
                algorithms: vec![ApplicationLayerProtocol::HTTP1_1],
            },
            b"h2" => ApplicationLayerProtocolNegotiationExtension {
                algorithms: vec![ApplicationLayerProtocol::HTTP2],
            },
            _ => ApplicationLayerProtocolNegotiationExtension { algorithms: vec![] },
        }
    }
}

enum ApplicationLayerProtocol {
    HTTP1_1,
    HTTP2,
}

impl ApplicationLayerProtocol {
    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        match self {
            ApplicationLayerProtocol::HTTP1_1 => {
                result.extend_from_slice(&((8) as u8).to_be_bytes());
                result.extend_from_slice("http/1.1".as_bytes());
            }
            ApplicationLayerProtocol::HTTP2 => {
                result.extend_from_slice(&((2) as u8).to_be_bytes());
                result.extend_from_slice("h2".as_bytes());
            }
        }
        result
    }
}

#[derive(Copy, Clone)]
enum SignatureAlgorithms {
    RSA_PKCS1_SHA256 = 0x0401,
    RSA_PKCS1_SHA384 = 0x0501,
    RSA_PKCS1_SHA512 = 0x0601,
    ECDSA_SHA256 = 0x0403,
    ECDSA_SHA384 = 0x0503,
    ECDSA_SHA512 = 0x0603,
    RSA_PSS_RSAE_SHA256 = 0x0804,
    RSA_PSS_RSAE_SHA384 = 0x0805,
    RSA_PSS_RSAE_SHA512 = 0x0806,
}

impl SignatureAlgorithmsExtension {
    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend_from_slice(
            &(ClientHelloExtensionType::SignatureAlgorithms as u16).to_be_bytes(),
        );
        result.extend_from_slice(&((self.algorithms.len() * 2 + 2) as u16).to_be_bytes());
        result.extend_from_slice(&((self.algorithms.len() * 2) as u16).to_be_bytes());
        for algorithm in &self.algorithms {
            result.extend_from_slice(&((*algorithm) as u16).to_be_bytes());
        }
        result
    }
}
