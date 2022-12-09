use std::{env,net::{TcpStream, UdpSocket}};

fn main() {
    let arg = env::args().nth(1).expect("missing required argument");
    let arg = arg.trim();

    if arg == "tcp" {
        let _ = TcpStream::connect("1.1.1.1:80").expect("(TCP)");
    } else if arg == "udp" {
        let socket = UdpSocket::bind("0.0.0.0:34254").expect("(UDP)");
        socket.connect("1.1.1.1:80").expect("(UDP)");
    } else {
        panic!("unknown argument used");
    }
}
