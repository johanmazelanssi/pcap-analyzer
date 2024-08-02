use std::collections::HashSet;
// use std::error::Error;
// use std::fs::File;
// use std::iter::FromIterator;
use std::net::IpAddr;
// use std::path::Path;
// use std::str::FromStr;

// use csv::ReaderBuilder;
use pnet_packet::ip::IpNextHeaderProtocol;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct IpAddrProtoIpid {
    ipaddr: IpAddr,
    proto: IpNextHeaderProtocol,
    // We use u32 because IPv6 use u32.
    ip_identification: u32,
}

impl IpAddrProtoIpid {
    pub fn new(
        ipaddr: IpAddr,
        proto: IpNextHeaderProtocol,
        ip_identification: u32,
    ) -> IpAddrProtoIpid {
        IpAddrProtoIpid {
            ipaddr,
            proto,
            ip_identification,
        }
    }
}

// TODO: remove pub later
#[derive(Debug)]
pub struct IpAddrProtoIpidC {
    pub s: HashSet<IpAddrProtoIpid>,
}

impl IpAddrProtoIpidC {
    pub fn new(s: HashSet<IpAddrProtoIpid>) -> IpAddrProtoIpidC {
        IpAddrProtoIpidC { s }
    }

    pub fn contains(&self, ipaddr_proto_ip_id: &IpAddrProtoIpid) -> bool {
        self.s.contains(ipaddr_proto_ip_id)
    }

    pub fn contains_tuple(
        &self,
        ipaddr: &IpAddr,
        proto: &IpNextHeaderProtocol,
        ip_id: u32,
    ) -> bool {
        let t = IpAddrProtoIpid::new(*ipaddr, *proto, ip_id);
        self.s.contains(&t)
    }
}
