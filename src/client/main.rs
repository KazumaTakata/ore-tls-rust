mod client_hello;
use client_hello::HandshakeProtocol;
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

fn parseRecordLayer(data: Vec<u8>) {
    let record_layer = client_hello::RecordLayer::from_byte_vector(data);
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

    println!("Hello, world!");
}
