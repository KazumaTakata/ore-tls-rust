use crate::change_cipher_spec::{self, ChangeCipherSpec};
use crate::client_hello::ClientHello;
use crate::finished::FinishedMessage;
use crate::handshake::{
    ApplicationLayerProtocol, ApplicationLayerProtocolNegotiationExtension, CipherSuites,
    ClientHelloExtensionType, HandshakeExtension, HandshakeProtocol, HandshakeType,
    SignatureAlgorithms, SignatureAlgorithmsExtension, SupportedGroupsExtension,
    SupportedVersionsExtension, TLSVersion,
};
use crate::server_hello::ServerHello;
use crate::{application_data, client_key_exchange};
use rand::rngs::OsRng;
use rand::RngCore;
use std::f32::consts::E;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;
use std::{io::Write, net::TcpStream, time::Duration};

#[derive(Debug)]
pub struct RecordLayer<'a> {
    pub content_type: ContentType,
    pub version: TLSVersion,
    pub message: HandshakeProtocol<'a>,
}

impl<'a> RecordLayer<'a> {
    pub fn new_client_hello<'b>() -> (RecordLayer<'b>, [u8; 32]) {
        let client_hello = ClientHello::new();
        let random = client_hello.random;
        let message = HandshakeProtocol::ClientHello(client_hello);

        return (
            RecordLayer {
                content_type: ContentType::Handshake,
                version: TLSVersion::V1_2,
                message: message,
            },
            random,
        );
    }

    pub fn new_client_change_cipher_spec<'b>() -> (RecordLayer<'b>, [u8; 32]) {
        let change_cipher_spec = ChangeCipherSpec::new(TLSVersion::V1_2);
        let message = HandshakeProtocol::ChangeCipherSpec(change_cipher_spec);

        return (
            RecordLayer {
                content_type: ContentType::ChangeCipherSpec,
                version: TLSVersion::V1_2,
                message: message,
            },
            [0; 32],
        );
    }

    pub fn new_client_key_change<'b>(public_key: [u8; 32]) -> (RecordLayer<'b>, [u8; 32]) {
        let client_key_exchange = client_key_exchange::ClientKeyExchange::new(public_key);
        let message = HandshakeProtocol::ClientKeyExchange(client_key_exchange);

        return (
            RecordLayer {
                content_type: ContentType::Handshake,
                version: TLSVersion::V1_2,
                message: message,
            },
            [0; 32],
        );
    }

    pub fn new_finished<'b>(
        master_secret: &[u8; 48],
        handshake_messages: &[u8],
        key: &[u8; 16],
        iv: Vec<u8>,
    ) -> (RecordLayer<'b>, [u8; 32]) {
        let finished_message = FinishedMessage::new(&master_secret, &handshake_messages, key, iv);

        let message = HandshakeProtocol::FinishedMessage(finished_message);

        return (
            RecordLayer {
                content_type: ContentType::Handshake,
                version: TLSVersion::V1_2,
                message: message,
            },
            [0; 32],
        );
    }

    pub fn new_application_data<'b>(
        data: Vec<u8>,
        key: &[u8; 16],
        iv: Vec<u8>,
    ) -> (RecordLayer<'b>, [u8; 32]) {
        let application_data = application_data::ApplicationData::new(data, key, iv);

        return (
            RecordLayer {
                content_type: ContentType::ApplicationData,
                version: TLSVersion::V1_2,
                message: HandshakeProtocol::ApplicationData(application_data),
            },
            [0; 32],
        );
    }

    pub fn to_byte_vector(&self) -> (Vec<u8>, Vec<u8>) {
        let mut result = vec![];
        result.push(self.content_type as u8);
        result.extend_from_slice(&(self.version as u16).to_be_bytes());
        let message = self.message.to_byte_vector();
        result.extend_from_slice(&(message.len() as u16).to_be_bytes());
        result.extend_from_slice(&message);
        return (result, message);
    }

    pub fn from_byte_vector(data: &'a [u8]) -> (RecordLayer<'a>, &'a [u8], &'a [u8]) {
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
            message,
            rest_message,
        );
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Handshake = 22,
    ApplicationData = 23,
    Alert,
    Heartbeat,
}
