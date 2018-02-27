use clap::{App, Arg, AppSettings};
use errors::ResultExt;

use std::net::SocketAddrV4;

use ::Result;

#[derive(Debug)]
pub struct Arguments {
    pub interface: String,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub reset: bool,
    pub send_null: bool,
}

impl Arguments {
    pub fn parse() -> Result<Arguments> {
        let matches = App::new("rshijack")
            .version(env!("CARGO_PKG_VERSION"))
            .setting(AppSettings::ColoredHelp)
            .about("Rust rewrite of shijack")
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
            .get_matches();

        let interface = matches.value_of("interface").unwrap();
        let src = matches.value_of("src").unwrap();
        let dst = matches.value_of("dst").unwrap();
        let reset = matches.occurrences_of("reset") > 0;
        let send_null = matches.occurrences_of("send-null") > 0;

        let src = src.parse().chain_err(|| "invalid src")?;
        let dst = dst.parse().chain_err(|| "invalid dst")?;

        Ok(Arguments {
            interface: interface.into(),
            src,
            dst,
            reset,
            send_null,
        })
    }
}
