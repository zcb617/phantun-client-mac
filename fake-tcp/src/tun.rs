use std::io;
#[cfg(target_os = "windows")]
use std::sync::Arc;

/// Abstract TUN device that works on both Linux and Windows.
#[async_trait::async_trait]
pub trait TunDevice: Send + Sync {
    /// Receive a raw IP packet from the TUN device.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Send a raw IP packet to the TUN device.
    async fn send(&self, buf: &[u8]) -> io::Result<usize>;

    /// Try to send a raw IP packet synchronously (non-blocking).
    fn try_send(&self, buf: &[u8]) -> io::Result<()>;

    /// Return the interface name.
    fn name(&self) -> String;
}

// ============================================================================
// Linux implementation using tokio-tun
// ============================================================================
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use tokio_tun::Tun;

    pub struct LinuxTun {
        tun: Tun,
    }

    impl LinuxTun {
        pub fn new(tun: Tun) -> Self {
            Self { tun }
        }
    }

    #[async_trait::async_trait]
    impl TunDevice for LinuxTun {
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.tun.recv(buf).await
        }

        async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.tun.send(buf).await
        }

        fn name(&self) -> String {
            self.tun.name().to_string()
        }

        fn try_send(&self, buf: &[u8]) -> io::Result<()> {
            self.tun.try_send(buf).map(|_| ())
        }
    }
}

// ============================================================================
// Windows implementation using WinDivert
// ============================================================================
#[cfg(target_os = "windows")]
pub mod windows {
    use super::*;
    use windivert::prelude::*;

    pub struct WinDivertTun {
        divert: Arc<WinDivert<NetworkLayer>>,
    }

    impl WinDivertTun {
        /// Create a new WinDivert-backed TUN device.
        ///
        /// `remote_addr` is the phantun server address. WinDivert will intercept
        /// all inbound TCP packets from this address/port, preventing Windows
        /// TCP/IP stack from seeing them (and thus preventing RST).
        pub fn new(remote_addr: std::net::SocketAddr) -> io::Result<Self> {
            let filter = format!(
                "tcp and ip.SrcAddr == {} and tcp.SrcPort == {}",
                remote_addr.ip(),
                remote_addr.port()
            );
            let divert =
                WinDivert::network(&filter, 0, WinDivertFlags::default()).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("WinDivertOpen failed: {}", e))
                })?;
            Ok(Self {
                divert: Arc::new(divert),
            })
        }
    }

    #[async_trait::async_trait]
    impl TunDevice for WinDivertTun {
        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let divert = self.divert.clone();
            let data = tokio::task::spawn_blocking(move || {
                let mut buffer = vec![0u8; 1500];
                loop {
                    match divert.recv_wait(&mut buffer, 100) {
                        Ok(Some(packet)) => {
                            let len = packet.data.len();
                            buffer.truncate(len);
                            return Ok(buffer);
                        }
                        Ok(None) => continue, // timeout, retry
                        Err(e) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("WinDivert recv failed: {}", e),
                            ));
                        }
                    }
                }
            })
            .await
            .unwrap_or_else(|e| Err(io::Error::new(io::ErrorKind::Other, e)))?;
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        }

        async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            let divert = self.divert.clone();
            let data = buf.to_vec();
            let len = buf.len();
            tokio::task::spawn_blocking(move || {
                let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(data) };
                packet.address.set_outbound(true);
                divert.send(&packet).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("WinDivert send failed: {}", e),
                    )
                })?;
                Ok(len)
            })
            .await
            .unwrap_or_else(|e| Err(io::Error::new(io::ErrorKind::Other, e)))
        }

        fn name(&self) -> String {
            "WinDivert".to_string()
        }

        fn try_send(&self, buf: &[u8]) -> io::Result<()> {
            let data = buf.to_vec();
            let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(data) };
            packet.address.set_outbound(true);
            self.divert.send(&packet).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("WinDivert send failed: {}", e),
                )
            })?;
            Ok(())
        }
    }
}
