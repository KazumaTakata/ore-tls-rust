use crate::handshake::{CipherSuites, HandshakeExtension, TLSVersion};

#[derive(Debug)]
pub struct ServerKeyExchange {
    pub ecdh_server_params: ECDHServerParams,
}

#[derive(Debug)]
pub struct ECDHServerParams {
    curve_type: CurveType,
    named_curve: NamedCurve,
    pub public_key: Vec<u8>,
    signature: Vec<u8>,
    signature_algorithm: SignatureAlgorithms,
}

#[derive(Debug)]
enum NamedCurve {
    X25519 = 0x001d,
    X448 = 0x001e,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
}

impl NamedCurve {
    pub fn from_u16(value: u16) -> NamedCurve {
        match value {
            0x001d => NamedCurve::X25519,
            0x001e => NamedCurve::X448,
            0x0017 => NamedCurve::secp256r1,
            0x0018 => NamedCurve::secp384r1,
            0x0019 => NamedCurve::secp521r1,
            _ => panic!("Invalid named curve."),
        }
    }
}

#[derive(Debug)]
enum SignatureAlgorithms {
    RSA_PKCS1_SHA256 = 0x0401,
}

impl SignatureAlgorithms {
    pub fn from_u16(value: u16) -> SignatureAlgorithms {
        match value {
            0x0401 => SignatureAlgorithms::RSA_PKCS1_SHA256,
            _ => panic!("Invalid signature algorithm."),
        }
    }
}

#[derive(Debug)]
enum CurveType {
    NamedCurve = 0x03,
}

impl CurveType {
    pub fn from_u8(value: u8) -> CurveType {
        match value {
            0x03 => CurveType::NamedCurve,
            _ => panic!("Invalid curve type."),
        }
    }
}

impl ServerKeyExchange {
    pub fn from_byte_vector(data: &[u8]) -> ServerKeyExchange {
        let length_1 = data[1];
        let length_2 = data[2];
        let length_3 = data[3];

        let length = u32::from_be_bytes([0, length_1, length_2, length_3]);

        let server_key_exchange_data = data[4..(4 + length as usize)].to_vec();

        let curve_type = CurveType::from_u8(server_key_exchange_data[0]);

        let named_curve =
            u16::from_be_bytes([server_key_exchange_data[1], server_key_exchange_data[2]]);

        let parsed_named_curve = NamedCurve::from_u16(named_curve);

        let public_key_length = server_key_exchange_data[3];

        let public_key = server_key_exchange_data[4..(4 + public_key_length as usize)].to_vec();

        let signature_algorithm = u16::from_be_bytes([
            server_key_exchange_data[4 + public_key_length as usize],
            server_key_exchange_data[5 + public_key_length as usize],
        ]);

        let parsed_signature_algorithm = SignatureAlgorithms::from_u16(signature_algorithm);

        let signature_length = u16::from_be_bytes([
            server_key_exchange_data[6 + public_key_length as usize],
            server_key_exchange_data[7 + public_key_length as usize],
        ]);

        let signature = server_key_exchange_data[(8 + public_key_length as usize)
            ..(8 + public_key_length as usize + signature_length as usize)]
            .to_vec();

        return ServerKeyExchange {
            ecdh_server_params: ECDHServerParams {
                curve_type: CurveType::NamedCurve,
                named_curve: parsed_named_curve,
                public_key: public_key,
                signature: signature,
                signature_algorithm: parsed_signature_algorithm,
            },
        };
    }
}
