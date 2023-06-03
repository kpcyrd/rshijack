use clap::{ArgAction, Parser};
use std::net::SocketAddr;

/// tcp connection hijacker, rust rewrite of shijack
#[derive(Debug, Parser)]
#[command(
    version,
    after_help = r#"The original shijack in C was written by spwny and released around 2001.
shijack credited cyclozine for inspiration."#
)]
pub struct Args {
    /// Interface we are going to hijack on
    pub interface: String,
    /// Source of the connection
    pub src: SocketAddr,
    /// Destination of the connection
    pub dst: SocketAddr,
    /// Initial seq number, if already known
    #[arg(long)]
    pub seq: Option<u32>,
    /// Initial ack number, if already known
    #[arg(long)]
    pub ack: Option<u32>,
    /// Reset the connection rather than hijacking it
    #[arg(short = 'r', long)]
    pub reset: bool,
    /// Desync original connection by sending 1kb of null bytes
    #[arg(short = '0', long)]
    pub send_null: bool,
    /// Reduce verbose output (can be used multiple times)
    #[arg(short, long, global = true, action(ArgAction::Count))]
    pub quiet: u8,
}
