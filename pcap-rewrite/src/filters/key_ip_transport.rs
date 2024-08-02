#[derive(Debug, PartialEq, Eq, Hash)]
pub struct KeyIpTransport<KeyIp, KeyTransport> {
    key_ip: KeyIp,
    key_transport_option: Option<KeyTransport>,
}

impl<KeyIp, KeyTransport> KeyIpTransport<KeyIp, KeyTransport> {
    pub fn new(
        key_ip: KeyIp,
        key_transport_option: Option<KeyTransport>,
    ) -> KeyIpTransport<KeyIp, KeyTransport> {
        KeyIpTransport {
            key_ip,
            key_transport_option,
        }
    }

    pub fn get_key_ip(&self) -> &KeyIp {
        &self.key_ip
    }

    pub fn get_key_transport_option(&self) -> &Option<KeyTransport> {
        &self.key_transport_option
    }
}

impl<KeyTransport> KeyIpTransport<(), KeyTransport> {
    pub fn new_transport(key_transport: KeyTransport) -> KeyIpTransport<(), KeyTransport> {
        KeyIpTransport::new((), Some(key_transport))
    }
}
