use std::net::IpAddr;

use log::warn;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;

use libpcap_tools::{Error, FiveTuple, ParseContext};

use crate::container::ipaddr_proto_ipid_container::IpAddrProtoIpid;
use crate::container::ipaddr_proto_port_container::IpAddrProtoPort;
use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;
use crate::filters::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;
use crate::filters::ipaddr_pair::IpAddrPair;
use crate::filters::key::Key;

pub fn parse_src_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv4 = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;
    Result::Ok(IpAddr::V4(ipv4.get_source()))
}

pub fn parse_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv4 = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    Result::Ok(IpAddr::V4(ipv4.get_destination()))
}

pub fn parse_src_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddrPair, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;
    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());
    Result::Ok(IpAddrPair::new(src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<Key<IpAddrProtoIpid, IpAddrProtoPort>, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());

    let ipddr_proto_ipid = IpAddrProtoIpid::new(
        src_ipaddr,
        ipv4_packet.get_next_level_protocol(),
        ipv4_packet.get_identification() as u32,
    );

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 20 && ipv4_packet.get_fragment_offset() == 0 {
                match TcpPacket::new(ipv4_payload) {
                    Some(ref tcp) => {
                        let dst_port = tcp.get_destination();
                        let key = Key::new(
                            ipddr_proto_ipid,
                            Some(IpAddrProtoPort::new(
                                src_ipaddr,
                                IpNextHeaderProtocols::Tcp,
                                dst_port,
                            )),
                        );
                        Ok(key)
                    }
                    None => {
                        warn!(
                            "Expected TCP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected TCP packet in Ipv4 but could not parse",
                        ))
                    }
                }
            } else {
                let key = Key::new(ipddr_proto_ipid, None);
                Ok(key)
            }
        }
        IpNextHeaderProtocols::Udp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 8 && ipv4_packet.get_fragment_offset() == 0 {
                match UdpPacket::new(ipv4_packet.payload()) {
                    Some(ref udp) => {
                        let dst_port = udp.get_destination();
                        let key = Key::new(
                            ipddr_proto_ipid,
                            Some(IpAddrProtoPort::new(
                                src_ipaddr,
                                IpNextHeaderProtocols::Udp,
                                dst_port,
                            )),
                        );
                        Ok(key)
                    }
                    None => {
                        warn!(
                            "Expected UDP packet in Ipv4 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected UDP packet in Ipv4 but could not parse",
                        ))
                    }
                }
            } else {
                let key = Key::new(ipddr_proto_ipid, None);
                Ok(key)
            }
        }
        _ => Ok(Key::new(
            ipddr_proto_ipid,
            Some(IpAddrProtoPort::new(
                src_ipaddr,
                ipv4_packet.get_next_level_protocol(),
                0,
            )),
        )),
    }
}

// pub fn parse_two_tuple_proto_ipid(
//     ctx: &ParseContext,
// =======
//         }
//         _ => {
//             let key = Key::new(
//                 ipddr_proto_ipid,
//                 Some(IpAddrProtoPort::new(
//                     src_ipaddr,
//                     ipv4_packet.get_next_level_protocol(),
//                     0,
//                 )),
//             );
//             Ok(key)
//         }
//     }
// }

pub fn parse_two_tuple_proto_ipid_five_tuple(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<Key<TwoTupleProtoIpid, FiveTuple>, Error> {
    let ipv4_packet =
        Ipv4Packet::new(payload).ok_or(Error::Pnet("Expected Ipv4 packet but could not parse"))?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());

    let two_tuple_proto_ipid = TwoTupleProtoIpid::new(
        src_ipaddr,
        dst_ipaddr,
        ipv4_packet.get_next_level_protocol().0,
        ipv4_packet.get_identification() as u32,
    );

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 20 && ipv4_packet.get_fragment_offset() == 0 {
                match TcpPacket::new(ipv4_payload) {
                    Some(ref tcp) => {
                        let src_port = tcp.get_source();
                        let dst_port = tcp.get_destination();
                        Ok(Key::new(
                            two_tuple_proto_ipid,
                            Some(FiveTuple {
                                src: src_ipaddr,
                                dst: dst_ipaddr,
                                proto: 6_u8,
                                src_port,
                                dst_port,
                            }),
                        ))
                    }
                    None => Err(Error::Pnet(
                        "Expected TCP packet in Ipv4 but could not parse",
                    )),
                }
            } else {
                let key = Key::new(two_tuple_proto_ipid, None);
                Ok(key)
            }
        }
        IpNextHeaderProtocols::Udp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            if ipv4_payload.len() >= 8 && ipv4_packet.get_fragment_offset() == 0 {
                match UdpPacket::new(ipv4_payload) {
                    Some(ref udp) => {
                        let src_port = udp.get_source();
                        let dst_port = udp.get_destination();
                        Ok(Key::new(
                            two_tuple_proto_ipid,
                            Some(FiveTuple {
                                src: src_ipaddr,
                                dst: dst_ipaddr,
                                proto: 17_u8,
                                src_port,
                                dst_port,
                            }),
                        ))
                    }
                    None => Err(Error::Pnet(
                        "Expected UDP packet in Ipv4 but could not parse",
                    )),
                }
            } else {
                let key = Key::new(two_tuple_proto_ipid, None);
                Ok(key)
            }
        }
        _ => {
            let key = Key::new(
                two_tuple_proto_ipid,
                Some(FiveTuple {
                    src: src_ipaddr,
                    dst: dst_ipaddr,
                    proto: ipv4_packet.get_next_level_protocol().0,
                    src_port: 0,
                    dst_port: 0,
                }),
            );
            Ok(key)
        }
    }
}

pub fn parse_two_tuple_proto_ipid____DEPRECATED(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpid, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;
    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());
    let proto = ipv4_packet.get_next_level_protocol().0;
    let ip_id = ipv4_packet.get_identification() as u32;
    Ok(TwoTupleProtoIpid::new(src_ipaddr, dst_ipaddr, proto, ip_id))
}

pub fn parse_five_tuple____DEPRECATED(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<FiveTuple, Error> {
    let ipv4_packet = Ipv4Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv4 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv4 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V4(ipv4_packet.get_source());
    let dst_ipaddr = IpAddr::V4(ipv4_packet.get_destination());

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            match TcpPacket::new(ipv4_payload) {
                Some(ref tcp) => {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    Ok(FiveTuple {
                        src: src_ipaddr,
                        dst: dst_ipaddr,
                        proto: 6_u8,
                        src_port,
                        dst_port,
                    })
                }
                None => {
                    warn!(
                        "Expected TCP packet in Ipv4 but could not parse at index {}",
                        ctx.pcap_index
                    );
                    Err(Error::Pnet(
                        "Expected TCP packet in Ipv4 but could not parse",
                    ))
                }
            }
        }
        IpNextHeaderProtocols::Udp => {
            let ipv4_payload = libpcap_analyzer::extract_payload_l3_ipv4(ctx, &ipv4_packet)?;
            match UdpPacket::new(ipv4_payload) {
                Some(ref udp) => {
                    let src_port = udp.get_source();
                    let dst_port = udp.get_destination();
                    Ok(FiveTuple {
                        src: src_ipaddr,
                        dst: dst_ipaddr,
                        proto: 17_u8,
                        src_port,
                        dst_port,
                    })
                }
                None => {
                    warn!(
                        "Expected UDP packet in Ipv4 but could not parse at index {}",
                        ctx.pcap_index
                    );
                    Err(Error::Pnet(
                        "Expected UDP packet in Ipv4 but could not parse",
                    ))
                }
            }
        }
        _ => Ok(FiveTuple {
            src: src_ipaddr,
            dst: dst_ipaddr,
            proto: ipv4_packet.get_next_level_protocol().0,
            src_port: 0,
            dst_port: 0,
        }),
    }
}

pub fn parse_two_tuple_proto_ipid_five_tuple____DEPRECATED(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpidFiveTuple, Error> {
    let two_tuple_proto_ipid = parse_two_tuple_proto_ipid____DEPRECATED(ctx, payload)?;
    let five_tuple = parse_five_tuple____DEPRECATED(ctx, payload)?;
    let two_tuple_proto_ipid_five_tuple =
        TwoTupleProtoIpidFiveTuple::new(Some(two_tuple_proto_ipid), Some(five_tuple));
    Ok(two_tuple_proto_ipid_five_tuple)
}
