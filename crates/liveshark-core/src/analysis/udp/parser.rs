use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::Linktype;

use super::error::UdpError;
use super::reader::UdpReader;

/// Parsed UDP packet with source/destination endpoints.
pub struct UdpPacket<'a> {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parse a UDP packet from a link-layer frame.
///
/// Returns `Ok(None)` when the payload is not UDP.
pub fn parse_udp_packet(
    linktype: Linktype,
    data: &[u8],
) -> Result<Option<UdpPacket<'_>>, UdpError> {
    let sliced = match linktype {
        Linktype::ETHERNET => {
            SlicedPacket::from_ethernet(data).map_err(|e| UdpError::Slice(e.to_string()))?
        }
        Linktype::RAW => SlicedPacket::from_ip(data).map_err(|e| UdpError::Slice(e.to_string()))?,
        _ => return Ok(None),
    };

    let net = sliced.net.ok_or(UdpError::MissingNetworkLayer)?;
    let transport = match sliced.transport {
        Some(transport) => transport,
        None => return Ok(None),
    };
    let udp = match transport {
        TransportSlice::Udp(udp) => udp,
        _ => return Ok(None),
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

    let ip_payload = net.ip_payload_ref().ok_or(UdpError::MissingIpPayload)?;
    let reader = UdpReader::new(ip_payload.payload);
    let payload = reader.payload_without_header()?;

    Ok(Some(UdpPacket {
        src_ip,
        src_port: udp.source_port(),
        dst_ip,
        dst_port: udp.destination_port(),
        payload,
    }))
}

#[cfg(test)]
mod tests {
    use super::parse_udp_packet;
    use crate::analysis::udp::error::UdpError;
    use etherparse::PacketBuilder;
    use pcap_parser::Linktype;

    #[test]
    fn parse_udp_ok() {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 0, 1], [192, 168, 0, 2], 64)
            .udp(6454, 6454);
        let payload = [1, 2, 3, 4];
        let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, &payload).unwrap();

        let parsed = parse_udp_packet(Linktype::ETHERNET, &packet).unwrap();
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.src_port, 6454);
        assert_eq!(parsed.dst_port, 6454);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_non_udp() {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(1000, 1001, 0, 0);
        let payload = [0u8; 4];
        let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, &payload).unwrap();

        let parsed = parse_udp_packet(Linktype::ETHERNET, &packet).unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_slice_error() {
        let data = [];
        let result = parse_udp_packet(Linktype::ETHERNET, &data);
        assert!(matches!(result, Err(UdpError::Slice(_))));
    }
}
