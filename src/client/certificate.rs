use x509_parser::prelude::{FromDer, X509Certificate};

use crate::handshake::{CipherSuites, HandshakeExtension, TLSVersion};

#[derive(Debug)]
pub struct TLSCertificate<'a> {
    certificate: X509Certificate<'a>,
}

impl<'a> TLSCertificate<'a> {
    pub fn from_byte_vector(data: &'a [u8]) -> TLSCertificate<'a> {
        let result = X509Certificate::from_der(data);
        let (_, cert) = result.expect("Could not parse certificate.");
        return TLSCertificate { certificate: cert };
    }
}
