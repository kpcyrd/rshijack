use crate::errors::*;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::MutablePacket;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::{transport_channel, TransportReceiver, TransportSender};

pub use pnet::packet::tcp::{ipv4_checksum, ipv6_checksum, TcpFlags};

use log::Level;
use pktparse::ethernet;
use pktparse::tcp::{self, TcpHeader};
use pktparse::{ip, ipv4, ipv6};

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct Connection {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: Arc<Mutex<u32>>,
    pub ack: Arc<Mutex<u32>>,
}

impl Connection {
    #[inline]
    pub fn new(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32) -> Connection {
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
        *self.seq.lock().unwrap()
    }

    #[inline]
    pub fn get_ack(&self) -> u32 {
        *self.ack.lock().unwrap()
    }

    #[inline]
    pub fn sendtcp(&mut self, tx: &mut TransportSender, flags: u16, data: &[u8]) -> Result<()> {
        sendtcp(
            tx,
            &self.src,
            &self.dst,
            flags,
            self.get_seq(),
            self.get_ack(),
            &data,
        )?;
        self.bump_seq(data.len() as u32);
        Ok(())
    }

    #[inline]
    pub fn ack(&mut self, tx: &mut TransportSender, mut ack: u32, data: &[u8]) -> Result<()> {
        ack += data.len() as u32;
        self.set_ack(ack);
        sendtcp(
            tx,
            &self.src,
            &self.dst,
            TcpFlags::ACK,
            self.get_seq(),
            ack,
            &[],
        )
    }

    #[inline]
    pub fn reset(&mut self, tx: &mut TransportSender) -> Result<()> {
        sendtcp(
            tx,
            &self.src,
            &self.dst,
            TcpFlags::RST,
            self.get_seq(),
            0,
            &[],
        )
    }
}

pub struct IpHeader {
    source_addr: IpAddr,
    dest_addr: IpAddr,
}

#[inline]
pub fn getseqack(interface: &str, src: &SocketAddr, dst: &SocketAddr) -> Result<Connection> {
    sniff(
        interface,
        Level::Debug,
        src,
        dst,
        |ip_hdr, tcp_hdr, remaining| {
            // skip packet if src/dst port doesn't match
            if (src.port() != tcp_hdr.source_port && src.port() != 0)
                || (dst.port() != tcp_hdr.dest_port && dst.port() != 0)
            {
                return Ok(None);
            }

            // skip packet if ack flag not set
            if !tcp_hdr.flag_ack {
                return Ok(None);
            }

            Ok(Some(Connection::new(
                SocketAddr::new(ip_hdr.source_addr, tcp_hdr.source_port),
                SocketAddr::new(ip_hdr.dest_addr, tcp_hdr.dest_port),
                tcp_hdr.sequence_no + remaining.len() as u32,
                tcp_hdr.ack_no,
            )))
        },
    )
}

#[inline]
pub fn recv(
    tx: &mut TransportSender,
    interface: &str,
    connection: &mut Connection,
    src: &SocketAddr,
    dst: &SocketAddr,
) -> Result<()> {
    let mut stdout = io::stdout();

    sniff(
        interface,
        Level::Trace,
        src,
        dst,
        |_ip_hdr, tcp_hdr, remaining| {
            // skip packet if src/dst port doesn't match
            if src.port() != tcp_hdr.source_port || dst.port() != tcp_hdr.dest_port {
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

            stdout.write_all(remaining)?;
            stdout.flush()?;

            connection.ack(tx, tcp_hdr.sequence_no, remaining)?;

            Ok(None)
        },
    )
}

fn ipv4_addr_match(filter: &Ipv4Addr, actual: &Ipv4Addr) -> bool {
    if filter == &Ipv4Addr::UNSPECIFIED {
        true
    } else {
        filter == actual
    }
}

fn ipv6_addr_match(filter: &Ipv6Addr, actual: &Ipv6Addr) -> bool {
    if filter == &Ipv6Addr::UNSPECIFIED {
        true
    } else {
        filter == actual
    }
}

pub fn sniff<F, T>(
    interface: &str,
    log_level: Level,
    src: &SocketAddr,
    dst: &SocketAddr,
    mut callback: F,
) -> Result<T>
where
    F: FnMut(IpHeader, TcpHeader, &[u8]) -> Result<Option<T>>,
{
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface)
        .context("Interface not found")?;

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => bail!("Unhandled channel type"),
        Err(e) => bail!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    while let Ok(packet) = rx.next() {
        trace!("received {:?}", packet);

        if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(&packet) {
            log!(log_level, "eth: {:?}", eth_frame);

            match (eth_frame.ethertype, src, dst) {
                (ethernet::EtherType::IPv4, SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                    if let Ok((remaining, ip_hdr)) = ipv4::parse_ipv4_header(remaining) {
                        log!(log_level, "ip4: {:?}", ip_hdr);

                        // skip packet if src/dst ip doesn't match
                        if !ipv4_addr_match(src.ip(), &ip_hdr.source_addr)
                            || !ipv4_addr_match(dst.ip(), &ip_hdr.dest_addr)
                        {
                            continue;
                        }

                        if ip_hdr.protocol == ip::IPProtocol::TCP {
                            if let Ok((remaining, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
                                log!(log_level, "tcp: {:?}", tcp_hdr);

                                let ip_hdr = IpHeader {
                                    source_addr: IpAddr::V4(ip_hdr.source_addr),
                                    dest_addr: IpAddr::V4(ip_hdr.dest_addr),
                                };
                                if let Some(result) = callback(ip_hdr, tcp_hdr, remaining)? {
                                    return Ok(result);
                                }
                            }
                        }
                    }
                }
                (ethernet::EtherType::IPv6, SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                    if let Ok((remaining, ip_hdr)) = ipv6::parse_ipv6_header(remaining) {
                        log!(log_level, "ip4: {:?}", ip_hdr);

                        // skip packet if src/dst ip doesn't match
                        if !ipv6_addr_match(src.ip(), &ip_hdr.source_addr)
                            || !ipv6_addr_match(dst.ip(), &ip_hdr.dest_addr)
                        {
                            continue;
                        }

                        if ip_hdr.next_header == ip::IPProtocol::TCP {
                            if let Ok((remaining, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
                                log!(log_level, "tcp: {:?}", tcp_hdr);

                                let ip_hdr = IpHeader {
                                    source_addr: IpAddr::V6(ip_hdr.source_addr),
                                    dest_addr: IpAddr::V6(ip_hdr.dest_addr),
                                };
                                if let Some(result) = callback(ip_hdr, tcp_hdr, remaining)? {
                                    return Ok(result);
                                }
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }

    bail!("Reading from interface failed!")
}

pub fn create_socket() -> Result<(TransportSender, TransportReceiver)> {
    let protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (tx, rx) = transport_channel(4096, protocol)?;
    Ok((tx, rx))
}

pub fn sendtcp(
    tx: &mut TransportSender,
    src: &SocketAddr,
    dst: &SocketAddr,
    flags: u16,
    seq: u32,
    ack: u32,
    data: &[u8],
) -> Result<()> {
    match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            sendtcpv4(tx, src, dst, flags, seq, ack, data)
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            sendtcpv6(tx, src, dst, flags, seq, ack, data)
        }
        _ => bail!("Invalid ipv4/ipv6 combination"),
    }
}

pub fn sendtcpv4(
    tx: &mut TransportSender,
    src: &SocketAddrV4,
    dst: &SocketAddrV4,
    flags: u16,
    seq: u32,
    ack: u32,
    data: &[u8],
) -> Result<()> {
    let tcp_len = MutableTcpPacket::minimum_packet_size() + data.len();
    let total_len = MutableIpv4Packet::minimum_packet_size() + tcp_len;

    let mut pkt_buf: Vec<u8> = vec![0; total_len];

    // populate ipv4
    let ipv4_header_len = match MutableIpv4Packet::minimum_packet_size().checked_div(4) {
        Some(l) => l as u8,
        None => bail!("Invalid header len"),
    };

    let mut ipv4 = MutableIpv4Packet::new(&mut pkt_buf).unwrap();
    ipv4.set_header_length(ipv4_header_len);
    ipv4.set_total_length(total_len as u16);

    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4.set_source(src.ip().to_owned());
    ipv4.set_version(4);
    ipv4.set_ttl(64);
    ipv4.set_destination(*dst.ip());
    ipv4.set_flags(Ipv4Flags::DontFragment);
    ipv4.set_options(&[]);

    // populate tcp
    gentcp(
        ipv4.payload_mut(),
        &SocketAddr::V4(*src),
        &SocketAddr::V4(*dst),
        flags,
        seq,
        ack,
        data,
    )?;

    match tx.send_to(ipv4, IpAddr::V4(*dst.ip())) {
        Ok(bytes) => {
            if bytes != total_len {
                bail!("short send count: {}", bytes)
            }
        }
        Err(e) => bail!("Could not send: {}", e),
    };

    Ok(())
}

pub fn sendtcpv6(
    tx: &mut TransportSender,
    src: &SocketAddrV6,
    dst: &SocketAddrV6,
    flags: u16,
    seq: u32,
    ack: u32,
    data: &[u8],
) -> Result<()> {
    let tcp_len = MutableTcpPacket::minimum_packet_size() + data.len();
    let total_len = MutableIpv6Packet::minimum_packet_size() + tcp_len;

    let mut pkt_buf: Vec<u8> = vec![0; total_len];

    // populate ipv6
    let mut ipv6 = MutableIpv6Packet::new(&mut pkt_buf).unwrap();
    ipv6.set_payload_length(tcp_len as u16);

    ipv6.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6.set_source(src.ip().to_owned());
    ipv6.set_version(6);
    ipv6.set_hop_limit(64);
    ipv6.set_destination(*dst.ip());

    // populate tcp
    gentcp(
        ipv6.payload_mut(),
        &SocketAddr::V6(*src),
        &SocketAddr::V6(*dst),
        flags,
        seq,
        ack,
        data,
    )?;

    match tx.send_to(ipv6, IpAddr::V6(*dst.ip())) {
        Ok(bytes) => {
            if bytes != total_len {
                bail!("short send count: {}", bytes)
            }
        }
        Err(e) => bail!("Could not send: {}", e),
    };

    Ok(())
}

fn gentcp(
    payload_mut: &mut [u8],
    src: &SocketAddr,
    dst: &SocketAddr,
    flags: u16,
    seq: u32,
    ack: u32,
    data: &[u8],
) -> Result<()> {
    let mut tcp = MutableTcpPacket::new(payload_mut).unwrap();

    let tcp_header_len = match MutableTcpPacket::minimum_packet_size().checked_div(4) {
        Some(l) => l as u8,
        None => bail!("Invalid header len"),
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

    let chk = match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            ipv4_checksum(&tcp.to_immutable(), src.ip(), dst.ip())
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            ipv6_checksum(&tcp.to_immutable(), src.ip(), dst.ip())
        }
        _ => bail!("Invalid ipv4/ipv6 combination"),
    };
    tcp.set_checksum(chk);
    Ok(())
}
