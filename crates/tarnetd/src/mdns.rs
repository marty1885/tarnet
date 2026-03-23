use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::sync::Arc;
use tokio::sync::mpsc;

const SERVICE_TYPE: &str = "_tarnet._tcp.local.";
const INSTANCE_PREFIX: &str = "tarnet-";

/// Interface name prefixes that should never be used for mDNS.
/// These are tunnels / VPNs where multicast doesn't work or isn't wanted.
const EXCLUDED_IFACE_PREFIXES: &[&str] = &["wg", "tun", "tap", "veth", "docker", "br-", "virbr"];

/// Start mDNS service registration and discovery.
/// Returns a channel that yields discovered peer addresses (host:port strings).
/// The returned handle keeps the daemon alive; drop it to stop.
pub fn start(
    peer_id_hex: &str,
    tcp_port: u16,
) -> Result<(mpsc::UnboundedReceiver<String>, MdnsHandle), String> {
    let mdns = ServiceDaemon::new().map_err(|e| format!("mDNS daemon: {}", e))?;

    // Disable tunnel/VPN/virtual interfaces where multicast doesn't work
    for iface in net_interfaces_to_exclude() {
        let _ = mdns.disable_interface(IfKind::Name(iface));
    }

    // Register our service
    let instance_name = format!("{}{}", INSTANCE_PREFIX, &peer_id_hex[..16]);
    let host = format!("{}.local.", instance_name);
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &host,
        "", // auto-detect IPs
        tcp_port,
        None, // no TXT properties needed; peer_id is in the instance name
    )
    .map_err(|e| format!("mDNS service info: {}", e))?
    .enable_addr_auto();

    mdns.register(info)
        .map_err(|e| format!("mDNS register: {}", e))?;
    log::info!("mDNS: registered as {}", instance_name);

    // Browse for other tarnet services
    let receiver = mdns
        .browse(SERVICE_TYPE)
        .map_err(|e| format!("mDNS browse: {}", e))?;

    let (tx, rx) = mpsc::unbounded_channel();
    let our_instance = instance_name.clone();

    std::thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let name = info.get_fullname().to_string();
                    // Skip our own registration
                    if name.contains(&our_instance) {
                        continue;
                    }
                    let port = info.get_port();
                    // Pick one address per peer: prefer non-link-local, then IPv4 over IPv6.
                    // Connecting to every address wastes links (they typically all
                    // route over the same physical NIC on a LAN).
                    let addrs: Vec<_> = info.get_addresses().iter().copied().collect();
                    let best = addrs
                        .iter()
                        .copied()
                        .filter(|a| !is_link_local(a))
                        .min_by_key(|a| if a.is_ipv4() { 0 } else { 1 })
                        .or_else(|| addrs.first().copied());
                    if let Some(addr) = best {
                        let peer_addr = format!("{}:{}", addr, port);
                        log::info!(
                            "mDNS: discovered peer at {} (from {} addrs)",
                            peer_addr,
                            addrs.len()
                        );
                        let _ = tx.send(peer_addr);
                    }
                }
                _ => {}
            }
        }
    });

    Ok((
        rx,
        MdnsHandle {
            _daemon: Arc::new(mdns),
        },
    ))
}

/// Keeps the mDNS daemon alive. Drop to unregister and stop.
pub struct MdnsHandle {
    _daemon: Arc<ServiceDaemon>,
}

/// Check if an IP address is link-local (169.254.x.x or fe80::).
fn is_link_local(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Returns interface names that match our exclusion prefixes.
fn net_interfaces_to_exclude() -> Vec<String> {
    let mut excluded = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return excluded;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if EXCLUDED_IFACE_PREFIXES.iter().any(|p| name.starts_with(p)) {
            log::debug!("mDNS: excluding interface {}", name);
            excluded.push(name);
        }
    }
    excluded
}
