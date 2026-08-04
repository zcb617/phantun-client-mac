use async_trait::async_trait;
use bytes::Bytes;
use fake_tcp::Stack;
use fake_tcp::packet::{MAX_PACKET_LEN, build_tcp_packet, parse_ip_packet};
use fake_tcp::tun::TunDevice;
use pnet_packet::Packet;
use pnet_packet::tcp::TcpFlags;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, timeout};

struct MockTun {
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

impl MockTun {
    fn new() -> (Arc<Self>, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(16);
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
impl TunDevice for MockTun {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let packet = self
            .incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "test input closed"))?;
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
        "mock-tun".to_owned()
    }

    fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
        self.outgoing
            .try_send(buffer.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "test output unavailable"))
    }
}

async fn next_packet(output: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    timeout(Duration::from_secs(1), output.recv())
        .await
        .expect("fake-TCP packet should arrive promptly")
        .expect("test output channel should remain open")
}

#[tokio::test]
async fn client_session_preserves_windows_fake_tcp_handshake_and_datagrams() {
    let local_ip = Ipv4Addr::new(192, 0, 2, 10);
    let remote: SocketAddr = "203.0.113.20:65009".parse().expect("valid remote address");
    let (tun, incoming, mut outgoing) = MockTun::new();
    let mut stack = Stack::new(vec![tun], local_ip, None);

    let connect = tokio::spawn(async move {
        stack
            .connect(remote)
            .await
            .expect("SYN/SYN-ACK/ACK sequence should establish")
    });

    let syn = next_packet(&mut outgoing).await;
    let syn_bytes = Bytes::from(syn);
    let (syn_ip, syn_tcp) =
        parse_ip_packet(&syn_bytes).expect("outbound SYN must be an IP/TCP packet");
    let local = SocketAddr::new(syn_ip.get_source(), syn_tcp.get_source());
    assert_eq!(syn_ip.get_source(), local_ip);
    assert_eq!(syn_ip.get_destination(), remote.ip());
    assert!((32768..=60999).contains(&syn_tcp.get_source()));
    assert_eq!(syn_tcp.get_destination(), remote.port());
    assert_eq!(syn_tcp.get_flags(), TcpFlags::SYN);

    incoming
        .send(build_tcp_packet(remote, local, 0, 1, TcpFlags::SYN | TcpFlags::ACK, None).to_vec())
        .await
        .expect("inject SYN-ACK");

    let socket = connect.await.expect("connect task must complete");
    let ack = next_packet(&mut outgoing).await;
    let ack_bytes = Bytes::from(ack);
    let (_, ack_tcp) = parse_ip_packet(&ack_bytes).expect("outbound ACK must be an IP/TCP packet");
    assert_eq!(ack_tcp.get_flags(), TcpFlags::ACK);

    assert!(socket.send(b"outbound-datagram").await.is_some());
    let outbound = next_packet(&mut outgoing).await;
    let outbound_bytes = Bytes::from(outbound);
    let (_, outbound_tcp) =
        parse_ip_packet(&outbound_bytes).expect("outbound data must be an IP/TCP packet");
    assert_eq!(outbound_tcp.payload(), b"outbound-datagram");

    incoming
        .send(
            build_tcp_packet(
                remote,
                local,
                1,
                18,
                TcpFlags::ACK,
                Some(b"inbound-datagram"),
            )
            .to_vec(),
        )
        .await
        .expect("inject inbound data");
    let mut received = [0_u8; MAX_PACKET_LEN];
    let size = timeout(Duration::from_secs(1), socket.recv(&mut received))
        .await
        .expect("inbound datagram should arrive");
    assert_eq!(
        &received[..size.expect("socket remains open")],
        b"inbound-datagram"
    );

    drop(socket);
    let reset = next_packet(&mut outgoing).await;
    let reset_bytes = Bytes::from(reset);
    let (_, reset_tcp) = parse_ip_packet(&reset_bytes).expect("close must emit an IP/TCP RST");
    assert_eq!(reset_tcp.get_flags(), TcpFlags::RST);
}
