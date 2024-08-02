#[derive(Debug)]
pub struct Key<KeyIp, KeyTransport> {
    key_ip: KeyIp,
    key_transport_option: Option<KeyTransport>,
}

impl<KeyIp, KeyTransport> Key<KeyIp, KeyTransport> {
    pub fn new(
        key_ip: KeyIp,
        key_transport_option: Option<KeyTransport>,
    ) -> Key<KeyIp, KeyTransport> {
        Key {
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

impl<KeyTransport> Key<(), KeyTransport> {
    pub fn new_transport(key_transport: KeyTransport) -> Key<(), KeyTransport> {
        Key::new((), Some(key_transport))
    }
}
