use x509_parser::prelude::CertificatePolicies;

use crate::{
    certificate::TLSCertificate, client_hello::ClientHello, server_hello::ServerHello,
    server_key_exchange::ServerKeyExchange,
};

#[derive(Copy, Clone, Debug)]
pub enum CipherSuites {
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
    pub fn from_u16(value: u16) -> CipherSuites {
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
pub enum HandshakeType {
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

pub enum ClientHelloExtensionType {
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

#[derive(Debug, Copy, Clone)]
pub enum SignatureAlgorithms {
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

#[derive(Copy, Clone, Debug)]
pub enum TLSVersion {
    V1_0 = 0x0301,
    V1_1 = 0x0302,
    V1_2 = 0x0303,
    V1_3 = 0x0304,
}

impl TLSVersion {
    pub fn from_u16(value: u16) -> TLSVersion {
        match value {
            0x0301 => TLSVersion::V1_0,
            0x0302 => TLSVersion::V1_1,
            0x0303 => TLSVersion::V1_2,
            0x0304 => TLSVersion::V1_3,
            _ => TLSVersion::V1_2,
        }
    }
}

#[derive(Debug)]
pub enum HandshakeExtension {
    SupportedVersions(SupportedVersionsExtension),
    SignatureAlgorithms(SignatureAlgorithmsExtension),
    ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiationExtension),
    SupportedGroups(SupportedGroupsExtension),
}

impl HandshakeExtension {
    pub fn from_byte_vector(data: Vec<u8>) -> HandshakeExtension {
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

#[derive(Debug)]
pub struct ApplicationLayerProtocolNegotiationExtension {
    pub algorithms: Vec<ApplicationLayerProtocol>,
}

#[derive(Debug)]
pub enum ApplicationLayerProtocol {
    HTTP1_1,
    HTTP2,
}

impl ApplicationLayerProtocol {
    pub fn to_byte_vector(&self) -> Vec<u8> {
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

impl ApplicationLayerProtocolNegotiationExtension {
    pub fn to_byte_vector(&self) -> Vec<u8> {
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
    pub fn from_byte_vector(data: Vec<u8>) -> ApplicationLayerProtocolNegotiationExtension {
        let _length = u16::from_be_bytes([data[0], data[1]]);
        let alpn_extension_length = u8::from_be_bytes([data[2]]);
        let protocol = data[3..(3 + alpn_extension_length as usize)].to_vec();
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

#[derive(Debug)]
pub struct SupportedVersionsExtension {
    pub versions: Vec<TLSVersion>,
}

impl SupportedVersionsExtension {
    pub fn to_byte_vector(&self) -> Vec<u8> {
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

#[derive(Debug)]
pub struct SignatureAlgorithmsExtension {
    pub algorithms: Vec<SignatureAlgorithms>,
}

impl SignatureAlgorithmsExtension {
    pub fn to_byte_vector(&self) -> Vec<u8> {
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

#[derive(Debug)]
pub struct SupportedGroupsExtension {
    pub groups: Vec<u16>,
}

impl SupportedGroupsExtension {
    pub fn to_byte_vector(&self) -> Vec<u8> {
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

#[derive(Debug)]
pub enum HandshakeProtocol<'a> {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(TLSCertificate<'a>),
    ServerKeyExchange(ServerKeyExchange),
    ServerHelloDone,
}

impl<'a> HandshakeProtocol<'a> {
    pub fn to_byte_vector(&self) -> Vec<u8> {
        match self {
            HandshakeProtocol::ClientHello(client_hello) => client_hello.to_byte_vector(),
            _ => vec![],
        }
    }

    pub fn from_byte_vector<'b>(data: &'b [u8]) -> HandshakeProtocol<'b> {
        let handshake_type = HandshakeType::try_from(data[0]).unwrap();
        match handshake_type {
            HandshakeType::ServerHello => {
                let server_hello = ServerHello::from_byte_vector(data);
                HandshakeProtocol::ServerHello(server_hello)
            }
            HandshakeType::Certificate => {
                let certificate = TLSCertificate::from_byte_vector(data);
                HandshakeProtocol::Certificate(certificate)
            }
            HandshakeType::ServerKeyExchange => {
                let server_key_exchange = ServerKeyExchange::from_byte_vector(data);
                HandshakeProtocol::ServerKeyExchange(server_key_exchange)
            }
            HandshakeType::ServerHelloDone => HandshakeProtocol::ServerHelloDone,
            _ => panic!("Unsupported handshake type"),
        }
    }
}
