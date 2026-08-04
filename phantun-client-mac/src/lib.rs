pub mod config;
pub mod forwarder;
pub mod macos_packet;
pub mod udp;

pub const UDP_TTL: std::time::Duration = std::time::Duration::from_secs(180);
