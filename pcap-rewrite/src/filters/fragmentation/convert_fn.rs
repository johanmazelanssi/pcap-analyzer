use std::collections::HashSet;
use std::iter::FromIterator;

use pnet_packet::ip::IpNextHeaderProtocol;

use libpcap_tools::FiveTuple;

use crate::container::five_tuple_container::FiveTupleC;
use crate::container::ipaddr_container::IpAddrC;
use crate::container::ipaddr_proto_ipid_container::IpAddrProtoIpid;
use crate::container::ipaddr_proto_ipid_container::IpAddrProtoIpidC;
use crate::container::ipaddr_proto_port_container::IpAddrProtoPort;
use crate::container::ipaddr_proto_port_container::IpAddrProtoPortC;
use crate::container::two_tuple_proto_ipid_container::TwoTupleProtoIpidC;
use crate::filters::fragmentation::two_tuple_proto_ipid::TwoTupleProtoIpid;
use crate::filters::key_ip_transport::KeyIpTransport;

pub fn convert_data_hs_to_src_ipaddrc(
    data_hs: &HashSet<KeyIpTransport<TwoTupleProtoIpid, FiveTuple>>,
) -> IpAddrC {
    let src_ipaddr_iter = data_hs
        .iter()
        .map(|key_ip_transport| key_ip_transport.get_key_ip())
        .map(|twptuple_proto_ipid| twptuple_proto_ipid.src);
    let src_ipaddr_hs = HashSet::from_iter(src_ipaddr_iter);
    IpAddrC::new(src_ipaddr_hs)
}

pub fn convert_data_hs_to_dst_ipaddrc(
    data_hs: &HashSet<KeyIpTransport<TwoTupleProtoIpid, FiveTuple>>,
) -> IpAddrC {
    let dst_ipaddr_iter = data_hs
        .iter()
        .map(|key_ip_transport| key_ip_transport.get_key_ip())
        .map(|twptuple_proto_ipid| twptuple_proto_ipid.dst);
    let dst_ipaddr_hs = HashSet::from_iter(dst_ipaddr_iter);
    IpAddrC::new(dst_ipaddr_hs)
}

pub fn convert_data_hs_to_src_dst_ipaddrc(
    data_hs: &HashSet<KeyIpTransport<TwoTupleProtoIpid, FiveTuple>>,
) -> IpAddrC {
    let src_ipaddr_iter = data_hs
        .iter()
        .map(|key_ip_transport| key_ip_transport.get_key_ip())
        .map(|twptuple_proto_ipid| twptuple_proto_ipid.src);
    let dst_ipaddr_iter = data_hs
        .iter()
        .map(|key_ip_transport| key_ip_transport.get_key_ip())
        .map(|twptuple_proto_ipid| twptuple_proto_ipid.dst);
    let src_dst_ipaddr_hs = HashSet::from_iter(src_ipaddr_iter.chain(dst_ipaddr_iter));
    IpAddrC::new(src_dst_ipaddr_hs)
}

pub fn convert_data_hs_to_src_ipaddr_proto_dst_port_container(
    data_hs: &HashSet<KeyIpTransport<TwoTupleProtoIpid, FiveTuple>>,
) -> IpAddrProtoPortC {
    let src_ipaddr_proto_dst_port_iter = data_hs
        .iter()
        .filter_map(|key_ip_transport| (*key_ip_transport.get_key_transport_option()).clone())
        .map(|five_tuple| {
            IpAddrProtoPort::new(
                five_tuple.src,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.dst_port,
            )
        });
    let dst_ipaddr_proto_src_port_iter = data_hs
        .iter()
        .filter_map(|key_ip_transport| (*key_ip_transport.get_key_transport_option()).clone())
        .map(|five_tuple| {
            IpAddrProtoPort::new(
                five_tuple.dst,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.src_port,
            )
        });
    let ipaddr_proto_port_hs =
        HashSet::from_iter(src_ipaddr_proto_dst_port_iter.chain(dst_ipaddr_proto_src_port_iter));
    IpAddrProtoPortC::new(ipaddr_proto_port_hs)
}

// TODO: add 2 functions to chose src/dst IpAddr/port
pub fn convert_data_hs_to_ipaddr_proto_ipid_ipaddr_proto_port(
    data_hs: &HashSet<KeyIpTransport<TwoTupleProtoIpid, FiveTuple>>,
) -> (IpAddrProtoIpidC, IpAddrProtoPortC) {
    let ipaddr_proto_ipid_hs: HashSet<_> = data_hs
        .iter()
        .map(|key_ip_transport| key_ip_transport.get_key_ip())
        .map(|two_tuple_proto_ipid| {
            IpAddrProtoIpid::new(
                two_tuple_proto_ipid.src,
                IpNextHeaderProtocol::new(two_tuple_proto_ipid.proto),
                two_tuple_proto_ipid.ip_id,
            )
        })
        .collect();

    let src_ipaddr_proto_dst_port_iter = data_hs
        .iter()
        .filter_map(|key_ip_transport| (*key_ip_transport.get_key_transport_option()).clone())
        .map(|five_tuple| {
            IpAddrProtoPort::new(
                five_tuple.src,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.dst_port,
            )
        });
    let dst_ipaddr_proto_src_port_iter = data_hs
        .iter()
        .filter_map(|key_ip_transport| (*key_ip_transport.get_key_transport_option()).clone())
        .map(|five_tuple| {
            IpAddrProtoPort::new(
                five_tuple.dst,
                IpNextHeaderProtocol::new(five_tuple.proto),
                five_tuple.src_port,
            )
        });
    let ipaddr_proto_port_hs =
        HashSet::from_iter(src_ipaddr_proto_dst_port_iter.chain(dst_ipaddr_proto_src_port_iter));

    (
        IpAddrProtoIpidC::new(ipaddr_proto_ipid_hs),
        IpAddrProtoPortC::new(ipaddr_proto_port_hs),
    )
}

pub fn convert_data_hs_to_ctuple(
    data_hs: &HashSet<KeyIpTransport<TwoTupleProtoIpid, FiveTuple>>,
) -> (TwoTupleProtoIpidC, FiveTupleC) {
    let two_tuple_proto_ipid_hs: HashSet<_> = data_hs
        .iter()
        .map(|key_ip_transport| key_ip_transport.get_key_ip())
        .cloned()
        .collect();
    let two_tuple_proto_ipid_hs_reversed = two_tuple_proto_ipid_hs
        .iter()
        .map(|two_tuple_proto_ipid| two_tuple_proto_ipid.get_reverse())
        .collect();
    let two_tuple_proto_ipid_container =
        TwoTupleProtoIpidC::new(two_tuple_proto_ipid_hs, two_tuple_proto_ipid_hs_reversed);

    let five_tuple_hs: HashSet<FiveTuple> = data_hs
        .iter()
        .filter_map(|key_ip_transport| (*key_ip_transport.get_key_transport_option()).clone())
        // .cloned()
        .collect();
    let five_tuple_hs_reversed = five_tuple_hs
        .iter()
        .map(|five_tuple| five_tuple.get_reverse())
        .collect();
    let five_tuple_c = FiveTupleC::new(five_tuple_hs, five_tuple_hs_reversed);

    (two_tuple_proto_ipid_container, five_tuple_c)
}
