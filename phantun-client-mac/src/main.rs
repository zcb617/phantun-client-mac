use fake_tcp::tun::TunDevice;
use log::info;
use phantun_client_mac::UDP_TTL;
use phantun_client_mac::config::{RuntimeConfig, command, load_config, select_remote_address};
use phantun_client_mac::forwarder::{ForwarderConfig, run_forwarder};
use phantun_client_mac::macos_packet::MacPacketDevice;
use phantun_client_mac::udp::new_udp_reuseport;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

fn discover_local_ipv4(remote_addr: SocketAddr) -> io::Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(remote_addr)?;
    match probe.local_addr()? {
        SocketAddr::V4(address) => Ok(*address.ip()),
        SocketAddr::V6(_) => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no IPv4 address available",
        )),
    }
}

fn discover_local_ipv6(remote_addr: SocketAddr) -> io::Result<SocketAddrV6> {
    let SocketAddr::V6(_) = remote_addr else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 source discovery requires an IPv6 remote",
        ));
    };
    let probe = std::net::UdpSocket::bind("[::]:0")?;
    probe.connect(remote_addr)?;
    match probe.local_addr()? {
        SocketAddr::V6(address) => Ok(address),
        SocketAddr::V4(_) => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no IPv6 address available",
        )),
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    if phantun_client_mac::macos_packet::run_cleanup_helper_if_requested()? {
        return Ok(());
    }

    pretty_env_logger::init();

    // Match the Windows client exactly: attempt the default configuration load
    // before clap handles --help/--version, then reload when --config is given.
    let mut loaded_config = load_config("phantun-client.json");
    let matches = command().get_matches();
    if let Some(config_path) = matches.get_one::<String>("config") {
        loaded_config = load_config(config_path);
    }
    let config = RuntimeConfig::from_loaded_config(&matches, loaded_config);

    let local_addr: SocketAddr = config.local.parse().expect("bad local address");
    let remote_addresses = tokio::net::lookup_host(&config.remote)
        .await
        .expect("bad remote address or host");
    let remote_addr = select_remote_address(remote_addresses, config.ipv4_only)
        .expect("unable to resolve remote host name");
    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = config
        .tun_local
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = config
        .tun_peer
        .parse()
        .expect("bad peer address for Tun interface");
    let (tun_local6, tun_peer6): (Option<std::net::Ipv6Addr>, Option<std::net::Ipv6Addr>) =
        if config.ipv4_only {
            (None, None)
        } else {
            (
                Some(
                    config
                        .tun_local6
                        .parse()
                        .expect("bad local address for Tun interface"),
                ),
                Some(
                    config
                        .tun_peer6
                        .parse()
                        .expect("bad peer address for Tun interface"),
                ),
            )
        };

    info!("TUN local: {}, TUN peer: {}", tun_local, tun_peer);
    if let (Some(local6), Some(peer6)) = (tun_local6, tun_peer6) {
        info!("TUN IPv6 local: {}, TUN IPv6 peer: {}", local6, peer6);
    }
    info!("UDP listen: {} -> remote {}", local_addr, remote_addr);

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let local_ipv6 = if remote_addr.is_ipv6() {
        Some(
            discover_local_ipv6(remote_addr)
                .expect("failed to determine local IPv6 address for the configured remote"),
        )
    } else {
        None
    };
    let tun_local_addr = if remote_addr.is_ipv4() {
        discover_local_ipv4(remote_addr).expect("failed to determine local IPv4 address")
    } else {
        Ipv4Addr::UNSPECIFIED
    };
    info!("Fake TCP local IP: {}", tun_local_addr);
    if let Some(local_ipv6) = local_ipv6 {
        info!("Fake TCP local IPv6: {}", local_ipv6.ip());
    }

    info!(
        "Opening macOS packet device for remote {}:{}",
        remote_addr.ip(),
        remote_addr.port()
    );
    let tun = MacPacketDevice::new(remote_addr, local_ipv6).map_err(|error_value| {
        io::Error::new(
            error_value.kind(),
            format!(
                "failed to open macOS packet device (administrator privileges may be required): {error_value}"
            ),
        )
    })?;
    info!("macOS packet device {} ready", tun.name());

    let udp_socket = Arc::new(new_udp_reuseport(local_addr).expect("failed to bind UDP listener"));
    let stack_ipv6 = local_ipv6.map(|address| *address.ip());
    run_forwarder(
        udp_socket,
        Arc::new(tun),
        ForwarderConfig {
            remote_addr,
            fake_tcp_local_ipv4: tun_local_addr,
            fake_tcp_local_ipv6: stack_ipv6,
            worker_count: num_cpus,
            udp_ttl: UDP_TTL,
        },
        CancellationToken::new(),
    )
    .await
}
