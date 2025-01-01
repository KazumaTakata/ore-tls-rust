use rand::rngs::OsRng;
use rand::RngCore;
use std::f32::consts::E;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io::Write, net::TcpStream, time::Duration};

fn generate_http_get_command(query: &str) -> String {
    format!("GET /{} HTTP/1.1\r\nHost: localhost:7878\r\n\r\n", query)
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

fn generate_session_id() -> Vec<u8> {
    let mut session_id = vec![0u8; 32]; // 32バイトの最大長を使用
    OsRng.fill_bytes(&mut session_id);
    session_id
}

struct RecordLayer {
    content_type: ContentType,
    version: TLSVersion,
    message: HandshakeProtocol,
}

impl RecordLayer {
    pub fn new() -> RecordLayer {
        RecordLayer {
            content_type: ContentType::Handshake,
            version: TLSVersion::V1_2,
            message: HandshakeProtocol::new(),
        }
    }

    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.push(self.content_type as u8);
        result.extend_from_slice(&(self.version as u16).to_be_bytes());
        let message = self.message.to_byte_vector();
        result.extend_from_slice(&(message.len() as u16).to_be_bytes());
        result.extend_from_slice(&message);
        result
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

struct ClientHello {
    content_type: ContentType,
    version: TLSVersion,
    length: u16,
}

struct HandshakeProtocol {
    handshake_type: HandshakeType,
    version: TLSVersion,
    random: [u8; 32],
    session_id: [u8; 32],
    cipher_suites: Vec<CipherSuites>,
    compression_methods: Vec<u8>,
    extensions: Vec<ClientHelloExtension>,
}

impl HandshakeProtocol {
    pub fn new() -> HandshakeProtocol {
        HandshakeProtocol {
            handshake_type: HandshakeType::ClientHello,
            version: TLSVersion::V1_2,
            random: generate_client_random(),
            session_id: generate_session_id().try_into().unwrap(),
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
                ClientHelloExtension::SupportedVersions(SupportedVersionsExtension {
                    versions: vec![TLSVersion::V1_2],
                }),
                ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithmsExtension {
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
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                    ApplicationLayerProtocolNegotiationExtension {
                        algorithms: vec![ApplicationLayerProtocol::HTTP1_1],
                    },
                ),
                ClientHelloExtension::SupportedGroups(SupportedGroupsExtension {
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

    fn to_byte_vector(&self) -> Vec<u8> {
        let mut result = vec![];
        result.push(self.handshake_type as u8);

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
                ClientHelloExtension::SupportedVersions(supported_versions) => {
                    client_hello_extension.extend_from_slice(&supported_versions.to_byte_vector());
                }
                ClientHelloExtension::SignatureAlgorithms(signature_algorithms) => {
                    client_hello_extension
                        .extend_from_slice(&signature_algorithms.to_byte_vector());
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn) => {
                    client_hello_extension.extend_from_slice(&alpn.to_byte_vector());
                }
                ClientHelloExtension::SupportedGroups(supported_groups) => {
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

enum ClientHelloExtension {
    SupportedVersions(SupportedVersionsExtension),
    SignatureAlgorithms(SignatureAlgorithmsExtension),
    ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiationExtension),
    SupportedGroups(SupportedGroupsExtension),
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

fn main() {
    let remote = "127.0.0.1:7878".parse().unwrap();
    let mut tcp_stream =
        TcpStream::connect_timeout(&remote, Duration::from_secs(1)).expect("Could not connect.");
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let record_layer = RecordLayer::new();

    let msg = record_layer.to_byte_vector();
    tcp_stream.write(&msg).unwrap();

    println!("Hello, world!");
}
