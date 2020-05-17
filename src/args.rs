use std::net::SocketAddrV4;
use structopt::StructOpt;
use structopt::clap::AppSettings;

/// tcp connection hijacker, rust rewrite of shijack
#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp], after_help=r#"The original shijack in C was written by spwny and released around 2001.
shijack credited cyclozine for inspiration."#)]
pub struct Args {
    /// The interface you are going to hijack on
    pub interface: String,
    /// The source of the connection
    pub src: SocketAddrV4,
    /// The destination of the connection
    pub dst: SocketAddrV4,
    /// Reset the connection rather than hijacking it
    #[structopt(short="r", long)]
    pub reset: bool,
    /// Prevent a desync by sending 1kb of null bytes
    #[structopt(short="0", long)]
    pub send_null: bool,
    /// Disable verbose output
    #[structopt(short, long, parse(from_occurrences))]
    pub quiet: u8,
}
