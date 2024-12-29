use std::{io::Write, net::TcpStream, time::Duration};

fn generate_http_get_command(query: &str) -> String {
    format!("GET /{} HTTP/1.1\r\nHost: localhost:7878\r\n\r\n", query)
}

fn main() {
    let remote = "127.0.0.1:7878".parse().unwrap();
    let mut tcp_stream =
        TcpStream::connect_timeout(&remote, Duration::from_secs(1)).expect("Could not connect.");
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let msg = generate_http_get_command("hello");

    tcp_stream.write(msg.as_bytes()).unwrap();

    println!("Hello, world!");
}
