mod certificate;
mod client_hello;
mod server_hello;
mod server_key_exchange;
use finished::FinishedMessage;
use generate_key::generate_key_iv;
use handshake::HandshakeProtocol;
use rand::rngs::OsRng;
use rand::RngCore;
use record_layer::RecordLayer;
use server_key_exchange::ServerKeyExchange;
use std::f32::consts::E;
use std::io::BufRead;
use std::os::unix::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    io::{self, Write},
    net::TcpStream,
    time::Duration,
};
use x25519_dalek::{EphemeralSecret, PublicKey};
use x509_parser::nom::Finish;

mod application_data;
mod change_cipher_spec;
mod client_key_exchange;
mod encrypt;
mod finished;
mod generate_key;
mod handshake;
mod record_layer;

struct ServerParams {
    public_key: [u8; 32],
    server_random: [u8; 32],
}

fn extract_parameter(layer: &[RecordLayer]) -> ServerParams {
    let mut server_params: ServerParams = ServerParams {
        public_key: [0; 32],
        server_random: [0; 32],
    };

    for record_layer in layer {
        match &record_layer.message {
            HandshakeProtocol::ServerKeyExchange(server_key_exchange) => {
                server_params.public_key = server_key_exchange
                    .ecdh_server_params
                    .public_key
                    .as_slice()
                    .try_into()
                    .expect("Public key must be 32 bytes");
            }
            HandshakeProtocol::ServerHello(server_hello) => {
                server_params.server_random = server_hello.random;
            }
            _ => {}
        }
    }

    return server_params;
}

fn parseRecordLayer(data: Vec<u8>, client_random: [u8; 32]) -> (ServerParams, Vec<u8>) {
    let (record_layer, message_1, rest_data) = RecordLayer::from_byte_vector(&data);
    let (record_layer_2, message_2, rest_data_2) = RecordLayer::from_byte_vector(&rest_data);
    let (record_layer_3, message_3, rest_data_3) = RecordLayer::from_byte_vector(&rest_data_2);
    let (record_layer_4, message_4, rest_data_4) = RecordLayer::from_byte_vector(&rest_data_3);

    println!("Record Layer1: {:#?}", record_layer);
    println!("Record Layer2: {:#?}", record_layer_2);
    println!("Record Layer3: {:#?}", record_layer_3);
    println!("Record Layer4: {:#?}", record_layer_4);
    println!("Rest Data: {:X?}", rest_data_4);

    let server_params =
        extract_parameter(&[record_layer, record_layer_2, record_layer_3, record_layer_4]);

    let all_messages = [message_1, message_2, message_3, message_4].concat();

    println!("server hello");
    println!("{:x?}", message_4);

    return (server_params, all_messages);
}

fn main() {
    let remote = "127.0.0.1:7878".parse().unwrap();
    let mut tcp_stream =
        TcpStream::connect_timeout(&remote, Duration::from_secs(1)).expect("Could not connect.");
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (record_layer, client_random) = RecordLayer::new_client_hello();
    let (msg, client_hello_message) = record_layer.to_byte_vector();
    tcp_stream.write(&msg).unwrap();

    // Wrap the stream in a BufReader, so we can use the BufRead methods
    let received: Vec<u8> = {
        let mut reader = io::BufReader::new(&mut tcp_stream);

        // Read current current data in the TcpStream
        reader.fill_buf().unwrap().to_vec()
    };

    let (server_params, all_messages) = parseRecordLayer(received, client_random);

    let my_secret_key = EphemeralSecret::random_from_rng(OsRng);
    let my_public_key = PublicKey::from(&my_secret_key);

    let (record_layer, _) = RecordLayer::new_client_key_change(my_public_key.to_bytes());
    let (client_key_exchange_msg, client_key_exchange_message) = record_layer.to_byte_vector();

    println!("client_hello_message");
    println!("{:x?}", client_key_exchange_message);

    let all_messages = [
        client_hello_message,
        all_messages,
        client_key_exchange_message,
    ]
    .concat();

    let (record_layer, _) = RecordLayer::new_client_change_cipher_spec();
    let (msg_change_cipher_spec, _) = record_layer.to_byte_vector();

    let (client_key, client_iv, master_secret) = generate_key_iv(
        server_params.public_key,
        my_secret_key,
        client_random,
        server_params.server_random,
    );

    let client_key = client_key.as_slice().try_into().unwrap();

    let master_secret = master_secret.as_slice().try_into().unwrap();

    println!("client_random: {:x?}", client_random);
    println!("master_secret: {:x?}", master_secret);

    let (record_layer, _) =
        RecordLayer::new_finished(master_secret, &all_messages, &client_key, client_iv.clone());

    let (msg_finished, _) = record_layer.to_byte_vector();

    let concated_msg = [
        client_key_exchange_msg,
        msg_change_cipher_spec,
        msg_finished,
    ]
    .concat();

    tcp_stream.write(&concated_msg).unwrap();

    // Wrap the stream in a BufReader, so we can use the BufRead methods
    let received: Vec<u8> = {
        let mut reader = io::BufReader::new(&mut tcp_stream);

        // Read current current data in the TcpStream
        reader.fill_buf().unwrap().to_vec()
    };

    let request_data = "GET /hello HTTP/1.1\r\nHost: localhost:7878\r\n\r\n"
        .to_string()
        .into_bytes();

    let (record_layer, _) = RecordLayer::new_application_data(request_data, &client_key, client_iv);

    let (msg_application, _) = record_layer.to_byte_vector();

    tcp_stream.write(&msg_application).unwrap();

    while (true) {
        print!("")
    }
}
