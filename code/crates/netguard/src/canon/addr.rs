//! Address classes (I6): every resolved or literal address is classified;
//! everything but `Public` is denied unless a grant names the class or the
//! literal.

use super::*;

/// Address classes. Everything but `Public` is denied unless a grant names
/// the class or the literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddrClass {
    Public,
    Loopback,
    LinkLocal,
    Metadata,
    Private,
    Reserved,
}

impl AddrClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddrClass::Public => "public",
            AddrClass::Loopback => "loopback",
            AddrClass::LinkLocal => "link_local",
            AddrClass::Metadata => "metadata",
            AddrClass::Private => "private",
            AddrClass::Reserved => "reserved",
        }
    }

    pub fn deny_reason(&self) -> Option<Reason> {
        match self {
            AddrClass::Public => None,
            AddrClass::Loopback => Some(Reason::LoopbackAddr),
            AddrClass::LinkLocal => Some(Reason::LinkLocalAddr),
            AddrClass::Metadata => Some(Reason::MetadataAddr),
            AddrClass::Private => Some(Reason::PrivateAddr),
            AddrClass::Reserved => Some(Reason::ReservedAddr),
        }
    }

    pub fn parse(s: &str) -> Option<AddrClass> {
        Some(match s {
            "public" => AddrClass::Public,
            "loopback" => AddrClass::Loopback,
            "link_local" => AddrClass::LinkLocal,
            "metadata" => AddrClass::Metadata,
            "private" => AddrClass::Private,
            "reserved" => AddrClass::Reserved,
            _ => return None,
        })
    }
}

/// Well-known cloud metadata endpoints (AWS/GCP/Azure 169.254.169.254, AWS
/// ECS 169.254.170.2, Alibaba 100.100.100.200, Oracle 192.0.0.192, AWS IMDS
/// IPv6 fd00:ec2::254).
fn is_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            matches!(a.octets(), [169, 254, 169, 254] | [169, 254, 170, 2] | [100, 100, 100, 200] | [192, 0, 0, 192])
        }
        IpAddr::V6(a) => a == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    }
}

pub fn classify_addr(ip: IpAddr) -> AddrClass {
    if is_metadata(ip) {
        return AddrClass::Metadata;
    }
    match ip {
        IpAddr::V4(a) => classify_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return classify_addr(IpAddr::V4(v4));
            }
            let seg = a.segments();
            // NAT64 well-known prefix 64:ff9b::/96 reaches embedded IPv4.
            if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0) {
                let v4 = Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8);
                return classify_addr(IpAddr::V4(v4));
            }
            if a.is_loopback() {
                AddrClass::Loopback
            } else if a.is_unspecified() || a.is_multicast() || is_mapped_or_compatible(&a) {
                AddrClass::Reserved
            } else if (seg[0] & 0xffc0) == 0xfe80 {
                AddrClass::LinkLocal
            } else if (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfec0 {
                AddrClass::Private
            } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                AddrClass::Reserved
            } else {
                AddrClass::Public
            }
        }
    }
}

fn classify_v4(a: Ipv4Addr) -> AddrClass {
    let o = a.octets();
    if a.is_loopback() {
        AddrClass::Loopback
    } else if a.is_link_local() {
        AddrClass::LinkLocal
    } else if a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64) {
        AddrClass::Private
    } else if o[0] == 0
        || a.is_multicast()
        || o[0] >= 240
        || a.is_broadcast()
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
    {
        AddrClass::Reserved
    } else {
        AddrClass::Public
    }
}
