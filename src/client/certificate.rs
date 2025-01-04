use x509_parser::prelude::{FromDer, X509Certificate};

use crate::handshake::{CipherSuites, HandshakeExtension, TLSVersion};

#[derive(Debug)]
pub struct TLSCertificate<'a> {
    certificate: X509Certificate<'a>,
}

impl<'a> TLSCertificate<'a> {
    pub fn from_byte_vector(data: &'a [u8]) -> TLSCertificate<'a> {
        let length_1 = data[7];
        let length_2 = data[8];
        let length_3 = data[9];

        let length = u32::from_be_bytes([0, length_1, length_2, length_3]);

        let result = X509Certificate::from_der(&data[10..(10 + length as usize)]);
        let (_, cert) = result.expect("Could not parse certificate.");
        return TLSCertificate { certificate: cert };
    }
}
