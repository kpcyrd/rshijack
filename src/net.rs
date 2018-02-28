use pnet::transport::{TransportSender, TransportReceiver, transport_channel};
use pnet::transport::TransportChannelType::Layer3;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Flags};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;

pub use pnet::packet::tcp::{TcpFlags, ipv4_checksum};

use log::Level;
use nom::IResult::Done;
use pktparse::ethernet;
use pktparse::ipv4;
use pktparse::tcp::{self, TcpHeader};
use pktparse::ipv4::IPv4Header;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::net::{IpAddr, SocketAddrV4};

use errors::{Result, ResultExt};


#[derive(Debug, Clone)]
pub struct Connection {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: Arc<Mutex<u32>>,
    pub ack: Arc<Mutex<u32>>,
}

impl Connection {
    #[inline]
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4, seq: u32, ack: u32) -> Connection {
        Connection {
            src,
            dst,
            seq: Arc::new(Mutex::new(seq)),
            ack: Arc::new(Mutex::new(ack)),
        }
    }

    #[inline]
    pub fn bump_seq(&self, inc: u32) {
        let mut guard = self.seq.lock().unwrap();
        *guard += inc;
    }

    #[inline]
    pub fn set_ack(&self, ack: u32) {
        let mut guard = self.ack.lock().unwrap();
        *guard = ack;
    }

    #[inline]
    pub fn get_seq(&self) -> u32 {
        (*self.seq.lock().unwrap()).clone()
    }

    #[inline]
    pub fn get_ack(&self) -> u32 {
        (*self.ack.lock().unwrap()).clone()
    }

    #[inline]
    pub fn sendtcp(&mut self, tx: &mut TransportSender, flags: u16, data: &[u8]) -> Result<()> {
        sendtcp(tx, &self.src, &self.dst, flags, self.get_seq(), self.get_ack(), &data)?;
        self.bump_seq(data.len() as u32);
        Ok(())
    }

    #[inline]
    pub fn ack(&mut self, tx: &mut TransportSender, mut ack: u32, data: &[u8]) -> Result<()> {
        ack += data.len() as u32;
        self.set_ack(ack);
        sendtcp(tx, &self.src, &self.dst, TcpFlags::ACK, self.get_seq(), ack, &[])
    }

    #[inline]
    pub fn reset(&mut self, tx: &mut TransportSender) -> Result<()> {
        sendtcp(tx, &self.src, &self.dst, TcpFlags::RST, self.get_seq(), 0, &[])
    }
}

#[inline]
pub fn getseqack(interface: &str, src: &SocketAddrV4, dst: &SocketAddrV4) -> Result<Connection> {
    sniff(interface, Level::Debug, src, dst, |ip_hdr, tcp_hdr, remaining| {
        // skip packet if src/dst port doesn't match
        if (src.port() != tcp_hdr.source_port && src.port() != 0) ||
           (dst.port() != tcp_hdr.dest_port && dst.port() != 0) {
                return Ok(None);
        }

        // skip packet if ack flag not set
        if !tcp_hdr.flag_ack {
            return Ok(None);
        }

        Ok(Some(Connection::new(
            SocketAddrV4::new(ip_hdr.source_addr, tcp_hdr.source_port),
            SocketAddrV4::new(ip_hdr.dest_addr, tcp_hdr.dest_port),
            tcp_hdr.sequence_no + remaining.len() as u32,
            tcp_hdr.ack_no,
        )))
    })
}


#[inline]
pub fn recv(tx: &mut TransportSender, interface: &str, connection: &mut Connection, src: &SocketAddrV4, dst: &SocketAddrV4) -> Result<()> {
    let mut stdout = io::stdout();

    sniff(interface, Level::Trace, src, dst, |_ip_hdr, tcp_hdr, remaining| {
        // skip packet if src/dst port doesn't match
        if src.port() != tcp_hdr.source_port ||
           dst.port() != tcp_hdr.dest_port {
                return Ok(None);
        }

        // skip packet if psh flag not set
        if !tcp_hdr.flag_psh {
            return Ok(None);
        }

        if connection.get_ack() >= tcp_hdr.sequence_no + remaining.len() as u32 {
            // filter duplicate packets
            return Ok(None);
        }

        stdout.write(remaining).unwrap();
        stdout.flush().unwrap();

        connection.ack(tx, tcp_hdr.sequence_no, remaining)?;

        Ok(None)
    })
}


pub fn sniff<F, T>(interface: &str, log_level: Level, src: &SocketAddrV4, dst: &SocketAddrV4, mut callback: F) -> Result<T>
        where F: FnMut(IPv4Header, TcpHeader, &[u8]) -> Result<Option<T>> {
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                        .filter(|iface: &NetworkInterface| iface.name == interface)
                        .next()
                        .chain_err(|| "Interface not found")?;

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => bail!("Unhandled channel type"),
        Err(e) => bail!("An error occurred when creating the datalink channel: {}", e)
    };

    while let Ok(packet) = rx.next() {
        trace!("received {:?}", packet);

        if let Done(remaining, eth_frame) = ethernet::parse_ethernet_frame(&packet) {
            log!(log_level, "eth: {:?}", eth_frame);

            match eth_frame.ethertype {
                ethernet::EtherType::IPv4 => {
                    if let Done(remaining, ip_hdr) = ipv4::parse_ipv4_header(remaining) {
                        log!(log_level, "ip4: {:?}", ip_hdr);

                        // skip packet if src/dst ip doesn't match
                        if *src.ip() != ip_hdr.source_addr ||
                           *dst.ip() != ip_hdr.dest_addr {
                               continue;
                        }

                        match ip_hdr.protocol {
                            ipv4::IPv4Protocol::TCP => {

                                if let Done(remaining, tcp_hdr) = tcp::parse_tcp_header(remaining) {
                                    log!(log_level, "tcp: {:?}", tcp_hdr);

                                    if let Some(result) = callback(ip_hdr, tcp_hdr, remaining)? {
                                        return Ok(result);
                                    }
                                }
                            },
                            _ => (),
                        }
                    }
                },
                _ => (),
            }
        }
    }

    Err("Reading from interface failed!".into())
}

pub fn create_socket() -> Result<(TransportSender, TransportReceiver)> {
    let protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (tx, rx) = transport_channel(4096, protocol)?;
    Ok((tx, rx))
}

pub fn sendtcp(tx: &mut TransportSender, src: &SocketAddrV4, dst: &SocketAddrV4, flags: u16, seq: u32, ack: u32, data: &[u8]) -> Result<()> {
    let tcp_len = MutableTcpPacket::minimum_packet_size() + data.len();
    let total_len = MutableIpv4Packet::minimum_packet_size() + tcp_len;

    let mut pkt_buf: Vec<u8> = vec![0; total_len];

    // populate ipv4
    let ipv4_header_len = match MutableIpv4Packet::minimum_packet_size().checked_div(4) {
        Some(l) => l as u8,
        None => bail!("Invalid header len")
    };

    let mut ipv4 = MutableIpv4Packet::new(&mut pkt_buf).unwrap();
    ipv4.set_header_length(ipv4_header_len);
    ipv4.set_total_length(total_len as u16);

    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4.set_source(src.ip().to_owned());
    ipv4.set_version(4);
    ipv4.set_ttl(64);
    ipv4.set_destination(dst.ip().clone());
    ipv4.set_flags(Ipv4Flags::DontFragment);
    ipv4.set_options(&[]);

    // populate tcp
    {
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();

        let tcp_header_len = match MutableTcpPacket::minimum_packet_size().checked_div(4) {
            Some(l) => l as u8,
            None => bail!("Invalid header len")
        };
        tcp.set_data_offset(tcp_header_len);

        tcp.set_source(src.port());
        tcp.set_destination(dst.port());
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_flags(flags);
        // set minimum window for ack packets
        let mut window = data.len() as u16;
        if window == 0 {
            window = 4;
        }
        tcp.set_window(window);

        tcp.set_payload(data);

        let chk = ipv4_checksum(&tcp.to_immutable(), src.ip().clone(), dst.ip().clone());
        tcp.set_checksum(chk);
    };

    match tx.send_to(ipv4, IpAddr::V4(dst.ip().clone())) {
        Ok(bytes) => if bytes != total_len { bail!("short send count: {}", bytes) },
        Err(e) => bail!("Could not send: {}", e),
    };

    Ok(())
}
