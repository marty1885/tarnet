use std::net::IpAddr;
use std::path::Path;
use tarnet_api::types::ServiceId;
use tarnet_expose::forward::{Direction, Request};

#[derive(Debug, Default)]
pub struct Policy(Vec<Rule>);

#[derive(Debug)]
struct Rule {
    permit: bool,
    source: Option<ServiceId>,
    direction: Option<Direction>,
    ports: (u16, u16),
    tcp: bool,
    udp: bool,
    address: AddressRange,
}

#[derive(Debug)]
struct AddressRange {
    first: IpAddr,
    last: IpAddr,
}

impl AddressRange {
    fn parse(s: &str) -> Result<Self, String> {
        if let Some((a, b)) = s.split_once('-') {
            let first: IpAddr = a.parse().map_err(|_| "invalid address range")?;
            let last: IpAddr = b.parse().map_err(|_| "invalid address range")?;
            if first.is_ipv4() != last.is_ipv4() || first > last {
                return Err("address range must be ordered and use one IP family".into());
            }
            return Ok(Self { first, last });
        }
        if let Some((ip, bits)) = s.split_once('/') {
            let ip: IpAddr = ip.parse().map_err(|_| "invalid CIDR address")?;
            let bits: u32 = bits.parse().map_err(|_| "invalid CIDR prefix")?;
            return match ip {
                IpAddr::V4(ip) if bits <= 32 => {
                    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                    let first = u32::from(ip) & mask;
                    Ok(Self { first: first.into(), last: (first | !mask).into() })
                }
                IpAddr::V6(ip) if bits <= 128 => {
                    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                    let first = u128::from(ip) & mask;
                    Ok(Self { first: first.into(), last: (first | !mask).into() })
                }
                _ => Err("CIDR prefix out of range".into()),
            };
        }
        let ip = s.parse().map_err(|_| "invalid IP address")?;
        Ok(Self { first: ip, last: ip })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.first.is_ipv4() == ip.is_ipv4() && self.first <= ip && ip <= self.last
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::parse(&s).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut rules = Vec::new();
        for (line, text) in text.lines().enumerate() {
            let words: Vec<_> = text.split('#').next().unwrap().split_whitespace().collect();
            if words.is_empty() { continue; }
            let result = (|| {
                if words.len() < 2 { return Err("expected permit/deny and source SID".into()); }
                let permit = match words[0] {
                    "permit" => true, "deny" => false,
                    _ => return Err("expected permit or deny".into()),
                };
                let source = if words[1] == "*" { None } else {
                    let sid = ServiceId::parse(words[1]).map_err(str::to_string)?;
                    if sid.is_all() || sid.is_local() { return Err("expected a real source SID".into()); }
                    Some(sid)
                };
                let mut rule = Rule { permit, source, direction: None, ports: (1, 65535), tcp: true, udp: true, address: AddressRange::parse("127.0.0.1")? };
                let mut seen = std::collections::HashSet::new();
                let mut i = 2;
                while i < words.len() {
                    let field = words[i];
                    if !seen.insert(field) { return Err(format!("duplicate {field}")); }
                    i += 1;
                    let value = *words.get(i).ok_or_else(|| format!("missing {field} value"))?;
                    i += 1;
                    match field {
                        "direction" => rule.direction = Some(match value {
                            "in" => Direction::In, "out" => Direction::Out,
                            _ => return Err("direction must be in or out".into()),
                        }),
                        "port" => {
                            let (a, b) = value.split_once('-').unwrap_or((value, value));
                            let a: u16 = a.parse().map_err(|_| "invalid port")?;
                            let b: u16 = b.parse().map_err(|_| "invalid port")?;
                            if a == 0 || a > b { return Err("invalid port range".into()); }
                            rule.ports = (a, b);
                        }
                        "address" => rule.address = AddressRange::parse(value)?,
                        "mode" => {
                            rule.tcp = false; rule.udp = false;
                            let mut modes = vec![value];
                            while i < words.len() && matches!(words[i], "tcp" | "udp") {
                                modes.push(words[i]); i += 1;
                            }
                            for mode in modes.iter().flat_map(|s| s.split(',')) {
                                match mode { "tcp" => rule.tcp = true, "udp" => rule.udp = true,
                                    _ => return Err("mode must be tcp and/or udp".into()) }
                            }
                        }
                        _ => return Err(format!("unknown field {field}")),
                    }
                }
                Ok(rule)
            })();
            rules.push(result.map_err(|e: String| format!("line {}: {e}", line + 1))?);
        }
        Ok(Self(rules))
    }

    pub fn permits(&self, source: ServiceId, req: &Request) -> bool {
        // IPv4-mapped IPv6 can reach IPv4 services. Match its effective IPv4
        // destination, preventing ::/0 rules from bypassing IPv4 restrictions.
        let address = match req.endpoint.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        self.0.iter().rev().find(|r| {
            r.source.is_none_or(|sid| sid == source)
                && r.direction.is_none_or(|d| d == req.direction)
                && r.ports.0 <= req.endpoint.port() && req.endpoint.port() <= r.ports.1
                && if req.udp { r.udp } else { r.tcp }
                && r.address.contains(address)
        }).is_some_and(|r| r.permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sid() -> ServiceId { ServiceId([42; 32]) }
    fn request(address: &str, direction: Direction, udp: bool) -> Request {
        Request { endpoint: address.parse().unwrap(), direction, udp }
    }
    #[test]
    fn defaults_and_last_match() {
        let r = request("127.0.0.1:3000", Direction::In, false);
        assert!(!Policy::default().permits(sid(), &r));
        let p = Policy::parse(&format!("permit {} port 3000-4000\ndeny * port 3306\n", sid())).unwrap();
        assert!(p.permits(sid(), &r));
        assert!(!p.permits(ServiceId([43;32]), &r));
        assert!(!p.permits(sid(), &request("127.0.0.1:3306", Direction::In, false)));
        assert!(!p.permits(sid(), &request("127.0.0.2:3000", Direction::In, false)));
    }
    #[test]
    fn direction_protocol_and_addresses() {
        let p = Policy::parse("permit * direction out port 80 mode tcp udp address 10.2.0.0/16\npermit * direction in port 53 mode udp address ::1\npermit * address 192.168.1.10-192.168.1.20").unwrap();
        assert!(p.permits(sid(), &request("10.2.3.4:80", Direction::Out, true)));
        assert!(!p.permits(sid(), &request("10.2.3.4:80", Direction::In, false)));
        assert!(!p.permits(sid(), &request("10.3.3.4:80", Direction::Out, false)));
        assert!(p.permits(sid(), &request("[::1]:53", Direction::In, true)));
        assert!(!p.permits(sid(), &request("[::1]:53", Direction::In, false)));
        assert!(p.permits(sid(), &request("192.168.1.20:9", Direction::In, false)));
        assert!(!p.permits(sid(), &request("192.168.1.21:9", Direction::In, false)));
        assert!(Policy::parse("permit * address ::/0").unwrap().permits(sid(), &request("[2001:db8::1]:80", Direction::In, false)));
    }
    #[test]
    fn malformed_rules_fail() {
        for s in ["allow *", "permit", "permit nope", "permit * port 0", "permit * port 9-2", "permit * mode sctp", "permit * address 1.2.3.4/33", "permit * address ::/129", "permit * address ::1-127.0.0.1", "permit * direction in direction out", "permit * typo yes"] {
            assert!(Policy::parse(s).is_err(), "{s}");
        }
    }
}
