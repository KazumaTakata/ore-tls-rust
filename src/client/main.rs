mod certificate;
mod client_hello;
mod server_hello;
mod server_key_exchange;
use rand::rngs::OsRng;
use rand::RngCore;
use std::f32::consts::E;
use std::io::BufRead;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    io::{self, Write},
    net::TcpStream,
    time::Duration,
};

mod generate_key;
mod handshake;

fn parseRecordLayer(data: Vec<u8>) {
    let (record_layer, rest_data) = client_hello::RecordLayer::from_byte_vector(&data);
    let (record_layer_2, rest_data_2) = client_hello::RecordLayer::from_byte_vector(&rest_data);
    let (record_layer_3, rest_data_3) = client_hello::RecordLayer::from_byte_vector(&rest_data_2);
    let (record_layer_4, rest_data_4) = client_hello::RecordLayer::from_byte_vector(&rest_data_3);

    println!("Record Layer1: {:#?}", record_layer);
    println!("Record Layer2: {:#?}", record_layer_2);
    println!("Record Layer3: {:#?}", record_layer_3);
    println!("Record Layer4: {:#?}", record_layer_4);
    println!("Rest Data: {:X?}", rest_data_4);
}

fn main() {
    let remote = "127.0.0.1:7878".parse().unwrap();
    let mut tcp_stream =
        TcpStream::connect_timeout(&remote, Duration::from_secs(1)).expect("Could not connect.");
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let record_layer = client_hello::RecordLayer::new();
    let msg = record_layer.to_byte_vector();
    tcp_stream.write(&msg).unwrap();

    // Wrap the stream in a BufReader, so we can use the BufRead methods
    let mut reader = io::BufReader::new(&mut tcp_stream);

    // Read current current data in the TcpStream
    let received: Vec<u8> = reader.fill_buf().unwrap().to_vec();

    println!("Received: {:X?}", received);

    parseRecordLayer(received);
}
