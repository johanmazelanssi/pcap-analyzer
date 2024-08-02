use std::net::IpAddr;

use log::warn;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;

use crate::filters::ipv6_utils;
use libpcap_tools::{Error, FiveTuple, ParseContext};

use crate::container::ipaddr_proto_ipid_container::IpAddrProtoIpid;
use crate::container::ipaddr_proto_port_container::IpAddrProtoPort;
use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;
use crate::filters::fragmentation::two_tuple_proto_ipid_five_tuple::TwoTupleProtoIpidFiveTuple;
use crate::filters::ipaddr_pair::IpAddrPair;
use crate::filters::key::Key;

pub fn parse_src_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv6 = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    Ok(IpAddr::V6(ipv6.get_source()))
}

pub fn parse_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddr, Error> {
    let ipv6 = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    Ok(IpAddr::V6(ipv6.get_destination()))
}

pub fn parse_src_dst_ipaddr(ctx: &ParseContext, payload: &[u8]) -> Result<IpAddrPair, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());
    Result::Ok(IpAddrPair::new(src_ipaddr, dst_ipaddr))
}

pub fn parse_src_ipaddr_proto_dst_port(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<Key<IpAddrProtoIpid, IpAddrProtoPort>, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());

    let (fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    let ip_id = match &fragment_packet_option {
        Some(fragment_packet) => fragment_packet.get_id(),
        None => 0,
    };

    let ipaddr_proto_ipid = IpAddrProtoIpid::new(src_ipaddr, IpNextHeaderProtocols::Tcp, ip_id);

    match l4_proto {
        IpNextHeaderProtocols::Tcp => {
            // TODO: add check on fragment offset
            if payload.len() >= 20 && fragment_packet_option.is_none() {
                match TcpPacket::new(payload) {
                    Some(ref tcp) => {
                        let dst_port = tcp.get_destination();
                        Ok(Key::new(
                            ipaddr_proto_ipid,
                            Some(IpAddrProtoPort::new(
                                src_ipaddr,
                                IpNextHeaderProtocols::Tcp,
                                dst_port,
                            )),
                        ))
                    }
                    None => {
                        warn!(
                            "Expected TCP packet in Ipv6 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected TCP packet in Ipv6 but could not parse",
                        ))
                    }
                }
            } else {
                let key = Key::new(ipaddr_proto_ipid, None);
                Ok(key)
            }
        }
        IpNextHeaderProtocols::Udp => {
            if payload.len() >= 8 && fragment_packet_option.is_none() {
                match UdpPacket::new(payload) {
                    Some(ref udp) => {
                        let dst_port = udp.get_destination();
                        Ok(Key::new(
                            ipaddr_proto_ipid,
                            Some(IpAddrProtoPort::new(
                                src_ipaddr,
                                IpNextHeaderProtocols::Udp,
                                dst_port,
                            )),
                        ))
                    }
                    None => {
                        warn!(
                            "Expected UDP packet in Ipv6 but could not parse at index {}",
                            ctx.pcap_index
                        );
                        Err(Error::Pnet(
                            "Expected UDP packet in Ipv6 but could not parse",
                        ))
                    }
                }
            } else {
                let key = Key::new(ipaddr_proto_ipid, None);
                Ok(key)
            }
        }
        _ => Ok(Key::new(
            ipaddr_proto_ipid,
            Some(IpAddrProtoPort::new(src_ipaddr, l4_proto, 0)),
        )),
    }
}

// pub fn parse_two_tuple_proto_ipid(
//     ctx: &ParseContext,
// =======
//         }
//         IpNextHeaderProtocols::Udp => {
//             if payload.len() >= 8 && fragment_packet_option.is_none() {
//                 match UdpPacket::new(payload) {
//                     Some(ref udp) => {
//                         let dst_port = udp.get_destination();
//                         Ok(Key::new(
//                             ipaddr_proto_ipid,
//                             Some(IpAddrProtoPort::new(
//                                 src_ipaddr,
//                                 IpNextHeaderProtocols::Udp,
//                                 dst_port,
//                             )),
//                         ))
//                     }
//                     None => Err(Error::Pnet(
//                         "Expected UDP packet in Ipv6 but could not parse",
//                     )),
//                 }
//             } else {
//                 let key = Key::new(ipaddr_proto_ipid, None);
//                 Ok(key)
//             }
//         }
//         _ => {
//             let key = Key::new(
//                 ipaddr_proto_ipid,
//                 Some(IpAddrProtoPort::new(src_ipaddr, l4_proto, 0)),
//             );
//             Ok(key)
//         }
//     }
// }

pub fn parse_two_tuple_proto_ipid_five_tuple(
    _ctx: &ParseContext,
    payload: &[u8],
) -> Result<Key<TwoTupleProtoIpid, FiveTuple>, Error> {
    let ipv6_packet =
        Ipv6Packet::new(payload).ok_or(Error::Pnet("Expected Ipv6 packet but could not parse"))?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());

    let (fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    let ip_id = match fragment_packet_option {
        Some(fragment_packet) => fragment_packet.get_id(),
        None => 0,
    };

    let two_tuple_proto_ipid = TwoTupleProtoIpid::new(src_ipaddr, dst_ipaddr, l4_proto.0, ip_id);

    match l4_proto {
        IpNextHeaderProtocols::Tcp => {
            if payload.len() >= 20 {
                match TcpPacket::new(payload) {
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
                        "Expected TCP packet in Ipv6 but could not parse",
                    )),
                }
            } else {
                let key = Key::new(two_tuple_proto_ipid, None);
                Ok(key)
            }
        }
        IpNextHeaderProtocols::Udp => {
            if payload.len() >= 8 {
                match UdpPacket::new(payload) {
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
                        "Expected UDP packet in Ipv6 but could not parse",
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
                    proto: l4_proto.0,
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
) -> Result<Option<TwoTupleProtoIpid>, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;
    let src_ipaddr = IpAddr::V6(ipv6_packet.get_destination());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());

    let (fragment_packet_option, l4_proto, _payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    let proto = l4_proto.0;

    match fragment_packet_option {
        Some(fragment_packet) => {
            let ip_id = fragment_packet.get_id();
            Ok(Some(TwoTupleProtoIpid::new(
                src_ipaddr, dst_ipaddr, proto, ip_id,
            )))
        }
        None => Ok(None),
    }
}

pub fn parse_five_tuple____DEPRECATED(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<FiveTuple, Error> {
    let ipv6_packet = Ipv6Packet::new(payload).ok_or_else(|| {
        warn!(
            "Expected Ipv6 packet but could not parse at index {}",
            ctx.pcap_index
        );
        Error::Pnet("Expected Ipv6 packet but could not parse")
    })?;

    let src_ipaddr = IpAddr::V6(ipv6_packet.get_source());
    let dst_ipaddr = IpAddr::V6(ipv6_packet.get_destination());

    let (_fragment_packet_option, l4_proto, payload) =
        ipv6_utils::get_fragment_packet_option_l4_protol4_payload(payload, &ipv6_packet)?;

    match l4_proto {
        IpNextHeaderProtocols::Tcp => match TcpPacket::new(payload) {
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
                    "Expected TCP packet in Ipv6 but could not parse",
                ))
            }
        },
        IpNextHeaderProtocols::Udp => match UdpPacket::new(payload) {
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
                    "Expected UDP packet in Ipv6 but could not parse",
                ))
            }
        },
        _ => Ok(FiveTuple {
            src: src_ipaddr,
            dst: dst_ipaddr,
            proto: l4_proto.0,
            src_port: 0,
            dst_port: 0,
        }),
    }
}

pub fn parse_two_tuple_proto_ipid_five_tuple____DEPRECATED(
    ctx: &ParseContext,
    payload: &[u8],
) -> Result<TwoTupleProtoIpidFiveTuple, Error> {
    Ok(TwoTupleProtoIpidFiveTuple::new(
        parse_two_tuple_proto_ipid____DEPRECATED(ctx, payload)?,
        // TODO: replace by dedicated error type to distinguish between Ipv6Packet parsing error and TcpPacket/UdpPacket error related to fragmentation
        parse_five_tuple____DEPRECATED(ctx, payload).ok(),
    ))
}
