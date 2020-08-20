use std::net::SocketAddr;
use structopt::clap::AppSettings;
use structopt::StructOpt;

/// tcp connection hijacker, rust rewrite of shijack
#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp], after_help=r#"The original shijack in C was written by spwny and released around 2001.
shijack credited cyclozine for inspiration."#)]
pub struct Args {
    /// Interface we are going to hijack on
    pub interface: String,
    /// Source of the connection
    pub src: SocketAddr,
    /// Destination of the connection
    pub dst: SocketAddr,
    /// Initial seq number, if already known
    #[structopt(long)]
    pub seq: Option<u32>,
    /// Initial ack number, if already known
    #[structopt(long)]
    pub ack: Option<u32>,
    /// Reset the connection rather than hijacking it
    #[structopt(short = "r", long)]
    pub reset: bool,
    /// Desync original connection by sending 1kb of null bytes
    #[structopt(short = "0", long)]
    pub send_null: bool,
    /// Disable verbose output
    #[structopt(short, long, parse(from_occurrences))]
    pub quiet: u8,
}
