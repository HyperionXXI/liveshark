use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::Linktype;

pub struct UdpPacket<'a> {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp_packet(linktype: Linktype, data: &[u8]) -> Option<UdpPacket<'_>> {
    let sliced = match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok()?,
        Linktype::RAW => SlicedPacket::from_ip(data).ok()?,
        _ => return None,
    };

    let net = sliced.net?;
    let transport = sliced.transport?;
    let udp = match transport {
        TransportSlice::Udp(udp) => udp,
        _ => return None,
    };

    let (src_ip, dst_ip) = match net {
        NetSlice::Ipv4(ref ipv4) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        ),
        NetSlice::Ipv6(ref ipv6) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        ),
    };

    let payload = net.ip_payload_ref()?.payload;
    if payload.len() < 8 {
        return None;
    }

    Some(UdpPacket {
        src_ip,
        src_port: udp.source_port(),
        dst_ip,
        dst_port: udp.destination_port(),
        payload: &payload[8..],
    })
}
