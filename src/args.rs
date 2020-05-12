use clap::{App, Arg, AppSettings};
use errors::ResultExt;

use std::net::SocketAddrV4;

use ::Result;

#[derive(Debug)]
pub struct Arguments {
    pub interface: String,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub reset: bool,
    pub send_null: bool,
    pub quiet: u8,
}

impl Arguments {
    pub fn parse() -> Result<Arguments> {
        let matches = App::new("rshijack")
            .version(env!("CARGO_PKG_VERSION"))
            .setting(AppSettings::ColoredHelp)
            .about("tcp connection hijacker, rust rewrite of shijack")
            .after_help(r#"The original shijack in C was written by spwny and released around 2001.
shijack credited cyclozine for inspiration."#)
            .arg(Arg::with_name("interface")
                .required(true)
                .help("The interface you are going to hijack on")
            )
            .arg(Arg::with_name("src")
                .required(true)
                .help("The source of the connection")
            )
            .arg(Arg::with_name("dst")
                .required(true)
                .help("The destination of the connection")
            )
            .arg(Arg::with_name("seq")
                .required(true)
                .help("Initial seq number")
            )
            .arg(Arg::with_name("ack")
                .required(true)
                .help("Initial ack number")
            )
            .arg(Arg::with_name("reset")
                .short("r")
                .long("reset")
                .help("Reset the connection rather than hijacking it")
            )
            .arg(Arg::with_name("send-null")
                .short("0")
                .long("send-null")
                .help("Prevent a desync by sending 1kb of null bytes")
            )
            .arg(Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .help("Disable verbose output")
                .multiple(true)
            )
            .get_matches();

        let interface = matches.value_of("interface").unwrap();
        let src = matches.value_of("src").unwrap();
        let dst = matches.value_of("dst").unwrap();
        let seq = matches.value_of("seq").unwrap().parse::<u32>().unwrap();
        let ack = matches.value_of("ack").unwrap().parse::<u32>().unwrap();
        let reset = matches.occurrences_of("reset") > 0;
        let send_null = matches.occurrences_of("send-null") > 0;
        let quiet = matches.occurrences_of("quiet") as u8;

        let src = src.parse().chain_err(|| "invalid src")?;
        let dst = dst.parse().chain_err(|| "invalid dst")?;

        Ok(Arguments {
            interface: interface.into(),
            src,
            dst,
            seq,
            ack,
            reset,
            send_null,
            quiet,
        })
    }
}
