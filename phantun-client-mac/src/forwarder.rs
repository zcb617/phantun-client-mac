use crate::udp::udp_recv_pktinfo;
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::tun::TunDevice;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock};
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Runtime values that define the Windows-compatible UDP-to-Phantun behavior.
#[derive(Debug, Clone)]
pub struct ForwarderConfig {
    pub remote_addr: SocketAddr,
    pub fake_tcp_local_ipv4: Ipv4Addr,
    pub fake_tcp_local_ipv6: Option<Ipv6Addr>,
    pub worker_count: usize,
    pub udp_ttl: Duration,
}

struct Connection {
    socket: Arc<Socket>,
    quit: CancellationToken,
}

/// Runs the client-side forwarding loop shared by the production entry point
/// and the app-level behavior tests. Its per-client connection lifecycle is
/// intentionally the same as the Windows client's loop.
pub async fn run_forwarder(
    udp_socket: Arc<UdpSocket>,
    packet_device: Arc<dyn TunDevice>,
    config: ForwarderConfig,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let remote_addr = config.remote_addr;
    let worker_count = config.worker_count.max(1);
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Connection>::new()));
    let mut stack = Stack::new(
        vec![packet_device],
        config.fake_tcp_local_ipv4,
        config.fake_tcp_local_ipv6,
    );
    let mut buffer = [0_u8; MAX_PACKET_LEN];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                cancel_all_connections(&connections).await;
                return Ok(());
            }
            received = udp_recv_pktinfo(&udp_socket, &mut buffer) => {
                let (size, udp_remote_addr, _udp_local_addr) = received?;
                let existing_socket = connections
                    .read()
                    .await
                    .get(&udp_remote_addr)
                    .map(|connection| connection.socket.clone());
                if let Some(socket) = existing_socket {
                    let _ = socket.send(&buffer[..size]).await;
                    continue;
                }

                info!("New UDP client from {}", udp_remote_addr);
                let Some(socket) = stack.connect(remote_addr).await else {
                    error!("Unable to connect to remote {}", remote_addr);
                    continue;
                };
                let socket = Arc::new(socket);

                if socket.send(&buffer[..size]).await.is_none() {
                    continue;
                }

                let packet_received = Arc::new(Notify::new());
                let quit = CancellationToken::new();
                assert!(
                    connections
                        .write()
                        .await
                        .insert(
                            udp_remote_addr,
                            Connection {
                                socket: socket.clone(),
                                quit: quit.clone(),
                            },
                        )
                        .is_none()
                );
                debug!("inserted fake TCP socket into connection table");

                spawn_connection_workers(
                    worker_count,
                    socket,
                    udp_socket.clone(),
                    udp_remote_addr,
                    remote_addr,
                    packet_received.clone(),
                    quit.clone(),
                );
                spawn_connection_timeout(
                    connections.clone(),
                    udp_remote_addr,
                    packet_received,
                    quit,
                    config.udp_ttl,
                );
            }
        }
    }
}

async fn cancel_all_connections(connections: &RwLock<HashMap<SocketAddr, Connection>>) {
    let active_connections = {
        let mut connections = connections.write().await;
        std::mem::take(&mut *connections)
    };
    for connection in active_connections.into_values() {
        connection.quit.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_connection_workers(
    worker_count: usize,
    socket: Arc<Socket>,
    udp_socket: Arc<UdpSocket>,
    udp_remote_addr: SocketAddr,
    remote_addr: SocketAddr,
    packet_received: Arc<Notify>,
    quit: CancellationToken,
) {
    for worker_index in 0..worker_count {
        let socket = socket.clone();
        let udp_socket = udp_socket.clone();
        let packet_received = packet_received.clone();
        let quit = quit.clone();

        tokio::spawn(async move {
            let mut tcp_buffer = [0_u8; MAX_PACKET_LEN];
            loop {
                tokio::select! {
                    result = socket.recv(&mut tcp_buffer) => {
                        match result {
                            Some(size) if size > 0 => {
                                if let Err(error_value) = udp_socket.send_to(&tcp_buffer[..size], udp_remote_addr).await {
                                    error!(
                                        "Unable to send UDP packet to {}: {}, closing connection",
                                        remote_addr,
                                        error_value
                                    );
                                    quit.cancel();
                                    return;
                                }
                            }
                            Some(_) => {}
                            None => {
                                debug!("removed fake TCP socket from connections table");
                                quit.cancel();
                                return;
                            }
                        }
                        packet_received.notify_one();
                    }
                    _ = quit.cancelled() => {
                        debug!("worker {} terminated", worker_index);
                        return;
                    }
                }
            }
        });
    }
}

fn spawn_connection_timeout(
    connections: Arc<RwLock<HashMap<SocketAddr, Connection>>>,
    udp_remote_addr: SocketAddr,
    packet_received: Arc<Notify>,
    quit: CancellationToken,
    udp_ttl: Duration,
) {
    tokio::spawn(async move {
        loop {
            let read_timeout = time::sleep(udp_ttl);
            let packet_received_fut = packet_received.notified();

            tokio::select! {
                _ = read_timeout => {
                    info!("No traffic seen in the last {:?}, closing connection", udp_ttl);
                    let connection = connections.write().await.remove(&udp_remote_addr);
                    debug!("removed fake TCP socket from connections table");
                    if let Some(connection) = connection {
                        connection.quit.cancel();
                    } else {
                        quit.cancel();
                    }
                    return;
                }
                _ = quit.cancelled() => {
                    connections.write().await.remove(&udp_remote_addr);
                    debug!("removed fake TCP socket from connections table");
                    return;
                }
                _ = packet_received_fut => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{ForwarderConfig, run_forwarder};
    use crate::udp::new_udp_reuseport;
    use async_trait::async_trait;
    use bytes::Bytes;
    use fake_tcp::packet::{build_tcp_packet, parse_ip_packet};
    use fake_tcp::tun::TunDevice;
    use pnet_packet::Packet;
    use pnet_packet::tcp::TcpFlags;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::{Mutex, mpsc};
    use tokio::time::{Duration, timeout};
    use tokio_util::sync::CancellationToken;

    struct MockPacketDevice {
        incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    }

    impl MockPacketDevice {
        fn new() -> (Arc<Self>, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
            let (incoming_tx, incoming_rx) = mpsc::channel(32);
            let (outgoing_tx, outgoing_rx) = mpsc::channel(32);
            (
                Arc::new(Self {
                    incoming: Mutex::new(incoming_rx),
                    outgoing: outgoing_tx,
                }),
                incoming_tx,
                outgoing_rx,
            )
        }
    }

    #[async_trait]
    impl TunDevice for MockPacketDevice {
        async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
            let packet =
                self.incoming.lock().await.recv().await.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "test input closed")
                })?;
            if packet.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test packet exceeds buffer",
                ));
            }
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }

        async fn send(&self, buffer: &[u8]) -> io::Result<usize> {
            self.outgoing
                .send(buffer.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "test output closed"))?;
            Ok(buffer.len())
        }

        fn name(&self) -> String {
            "mock-packet-device".to_owned()
        }

        fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
            self.outgoing
                .try_send(buffer.to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "test output unavailable"))
        }
    }

    async fn next_packet(output: &mut mpsc::Receiver<Vec<u8>>) -> Bytes {
        Bytes::from(
            timeout(Duration::from_secs(1), output.recv())
                .await
                .expect("fake-TCP packet should arrive promptly")
                .expect("test output channel should remain open"),
        )
    }

    fn fake_tcp_local(packet: &Bytes) -> SocketAddr {
        let (ip_packet, tcp_packet) =
            parse_ip_packet(packet).expect("outbound packet must be IP/TCP");
        SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source())
    }

    fn packet_flags(packet: &Bytes) -> u8 {
        let (_, tcp_packet) = parse_ip_packet(packet).expect("packet must be IP/TCP");
        tcp_packet.get_flags()
    }

    fn packet_payload(packet: &Bytes) -> Vec<u8> {
        let (_, tcp_packet) = parse_ip_packet(packet).expect("packet must be IP/TCP");
        tcp_packet.payload().to_vec()
    }

    async fn start_forwarder(
        device: Arc<MockPacketDevice>,
        remote: SocketAddr,
        udp_ttl: Duration,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = Arc::new(
            new_udp_reuseport("127.0.0.1:0".parse().expect("valid UDP listener"))
                .expect("UDP listener must bind"),
        );
        let listener_addr = listener.local_addr().expect("listener address");
        let shutdown = CancellationToken::new();
        let packet_device: Arc<dyn TunDevice> = device;
        let task = tokio::spawn(run_forwarder(
            listener,
            packet_device,
            ForwarderConfig {
                remote_addr: remote,
                fake_tcp_local_ipv4: Ipv4Addr::new(192, 0, 2, 10),
                fake_tcp_local_ipv6: None,
                worker_count: 2,
                udp_ttl,
            },
            shutdown.clone(),
        ));
        (listener_addr, shutdown, task)
    }

    async fn establish_client(
        client: &UdpSocket,
        listener_addr: SocketAddr,
        initial_datagram: &[u8],
        remote: SocketAddr,
        incoming: &mpsc::Sender<Vec<u8>>,
        outgoing: &mut mpsc::Receiver<Vec<u8>>,
    ) -> SocketAddr {
        client
            .send_to(initial_datagram, listener_addr)
            .await
            .expect("UDP client must send initial datagram");
        let syn = next_packet(outgoing).await;
        assert_eq!(packet_flags(&syn), TcpFlags::SYN);
        let local = fake_tcp_local(&syn);
        incoming
            .send(
                build_tcp_packet(remote, local, 0, 1, TcpFlags::SYN | TcpFlags::ACK, None).to_vec(),
            )
            .await
            .expect("mock remote must send SYN-ACK");
        let ack = next_packet(outgoing).await;
        assert_eq!(packet_flags(&ack), TcpFlags::ACK);
        let payload = next_packet(outgoing).await;
        assert_eq!(packet_flags(&payload), TcpFlags::ACK);
        assert_eq!(packet_payload(&payload), initial_datagram);
        local
    }

    #[tokio::test]
    async fn forwards_udp_in_both_directions_and_keeps_clients_isolated() {
        let remote: SocketAddr = "203.0.113.20:65009".parse().expect("valid remote");
        let (device, incoming, mut outgoing) = MockPacketDevice::new();
        let (listener_addr, shutdown, task) =
            start_forwarder(device, remote, Duration::from_secs(2)).await;
        let client_a = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("first UDP client must bind");
        let client_b = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("second UDP client must bind");

        let local_a = establish_client(
            &client_a,
            listener_addr,
            b"first-client-initial",
            remote,
            &incoming,
            &mut outgoing,
        )
        .await;
        incoming
            .send(
                build_tcp_packet(
                    remote,
                    local_a,
                    1,
                    1,
                    TcpFlags::ACK,
                    Some(b"reply-for-first"),
                )
                .to_vec(),
            )
            .await
            .expect("mock remote must send first reply");
        let mut first_buffer = [0_u8; 64];
        let (first_size, first_sender) = timeout(
            Duration::from_secs(1),
            client_a.recv_from(&mut first_buffer),
        )
        .await
        .expect("first client must receive reply")
        .expect("first client receive succeeds");
        assert_eq!(first_sender, listener_addr);
        assert_eq!(&first_buffer[..first_size], b"reply-for-first");

        client_a
            .send_to(b"first-client-follow-up", listener_addr)
            .await
            .expect("existing client must send follow-up datagram");
        let follow_up = next_packet(&mut outgoing).await;
        assert_eq!(packet_flags(&follow_up), TcpFlags::ACK);
        assert_eq!(packet_payload(&follow_up), b"first-client-follow-up");

        let local_b = establish_client(
            &client_b,
            listener_addr,
            b"second-client-initial",
            remote,
            &incoming,
            &mut outgoing,
        )
        .await;
        assert_ne!(local_a.port(), local_b.port());
        incoming
            .send(
                build_tcp_packet(
                    remote,
                    local_b,
                    1,
                    1,
                    TcpFlags::ACK,
                    Some(b"reply-for-second"),
                )
                .to_vec(),
            )
            .await
            .expect("mock remote must send second reply");
        let mut second_buffer = [0_u8; 64];
        let (second_size, second_sender) = timeout(
            Duration::from_secs(1),
            client_b.recv_from(&mut second_buffer),
        )
        .await
        .expect("second client must receive reply")
        .expect("second client receive succeeds");
        assert_eq!(second_sender, listener_addr);
        assert_eq!(&second_buffer[..second_size], b"reply-for-second");

        let mut unexpected = [0_u8; 64];
        assert!(
            timeout(
                Duration::from_millis(100),
                client_a.recv_from(&mut unexpected),
            )
            .await
            .is_err(),
            "a reply for one UDP client must not be sent to another client"
        );

        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("forwarder must stop after explicit shutdown")
            .expect("forwarder task must not panic")
            .expect("forwarder shutdown must succeed");
    }

    #[tokio::test]
    async fn idle_timeout_closes_the_session_and_allows_a_new_one() {
        let remote: SocketAddr = "203.0.113.21:65009".parse().expect("valid remote");
        let (device, incoming, mut outgoing) = MockPacketDevice::new();
        let (listener_addr, shutdown, task) =
            start_forwarder(device, remote, Duration::from_millis(150)).await;
        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP client must bind");

        let _first_local = establish_client(
            &client,
            listener_addr,
            b"initial",
            remote,
            &incoming,
            &mut outgoing,
        )
        .await;
        let reset = next_packet(&mut outgoing).await;
        assert_eq!(packet_flags(&reset), TcpFlags::RST);

        client
            .send_to(b"after-timeout", listener_addr)
            .await
            .expect("UDP client must retry after timeout");
        let new_syn = next_packet(&mut outgoing).await;
        assert_eq!(packet_flags(&new_syn), TcpFlags::SYN);
        let second_local = fake_tcp_local(&new_syn);
        incoming
            .send(
                build_tcp_packet(
                    remote,
                    second_local,
                    0,
                    1,
                    TcpFlags::SYN | TcpFlags::ACK,
                    None,
                )
                .to_vec(),
            )
            .await
            .expect("mock remote must accept replacement session");
        let second_ack = next_packet(&mut outgoing).await;
        assert_eq!(packet_flags(&second_ack), TcpFlags::ACK);
        let second_payload = next_packet(&mut outgoing).await;
        assert_eq!(packet_payload(&second_payload), b"after-timeout");

        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("forwarder must stop after explicit shutdown")
            .expect("forwarder task must not panic")
            .expect("forwarder shutdown must succeed");
    }

    #[tokio::test]
    async fn remote_reset_closes_the_session_and_allows_a_new_one() {
        let remote: SocketAddr = "203.0.113.22:65009".parse().expect("valid remote");
        let (device, incoming, mut outgoing) = MockPacketDevice::new();
        let (listener_addr, shutdown, task) =
            start_forwarder(device, remote, Duration::from_secs(2)).await;
        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP client must bind");

        let first_local = establish_client(
            &client,
            listener_addr,
            b"before-reset",
            remote,
            &incoming,
            &mut outgoing,
        )
        .await;
        incoming
            .send(build_tcp_packet(remote, first_local, 1, 1, TcpFlags::RST, None).to_vec())
            .await
            .expect("mock remote must reset the session");
        let reset = next_packet(&mut outgoing).await;
        assert_eq!(packet_flags(&reset), TcpFlags::RST);

        client
            .send_to(b"after-reset", listener_addr)
            .await
            .expect("UDP client must retry after remote reset");
        let new_syn = next_packet(&mut outgoing).await;
        assert_eq!(packet_flags(&new_syn), TcpFlags::SYN);
        let second_local = fake_tcp_local(&new_syn);
        incoming
            .send(
                build_tcp_packet(
                    remote,
                    second_local,
                    0,
                    1,
                    TcpFlags::SYN | TcpFlags::ACK,
                    None,
                )
                .to_vec(),
            )
            .await
            .expect("mock remote must accept replacement session");
        let second_ack = next_packet(&mut outgoing).await;
        assert_eq!(packet_flags(&second_ack), TcpFlags::ACK);
        let second_payload = next_packet(&mut outgoing).await;
        assert_eq!(packet_payload(&second_payload), b"after-reset");

        shutdown.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("forwarder must stop after explicit shutdown")
            .expect("forwarder task must not panic")
            .expect("forwarder shutdown must succeed");
    }
}
