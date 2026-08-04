use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

/// Matches the Windows client behavior: bind one UDP socket and use its bound
/// address as the local destination when packet-info APIs are unavailable.
pub fn new_udp_reuseport(local_addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(local_addr)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket)
}

pub async fn udp_recv_pktinfo(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr, IpAddr)> {
    let (size, remote_addr) = socket.recv_from(buffer).await?;
    let local_addr = socket.local_addr()?.ip();
    Ok((size, remote_addr, local_addr))
}

#[cfg(test)]
mod tests {
    use super::{new_udp_reuseport, udp_recv_pktinfo};

    #[tokio::test]
    async fn listener_binds_the_requested_address_and_returns_to_sender() {
        let listener = new_udp_reuseport("127.0.0.1:0".parse().expect("valid listener"))
            .expect("UDP listener must bind");
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("sender must bind");
        let listener_addr = listener.local_addr().expect("listener address");
        sender
            .send_to(b"phantun", listener_addr)
            .await
            .expect("sender must write");

        let mut buffer = [0_u8; 64];
        let (size, sender_addr, destination_ip) = udp_recv_pktinfo(&listener, &mut buffer)
            .await
            .expect("listener must receive");
        assert_eq!(&buffer[..size], b"phantun");
        assert_eq!(sender_addr, sender.local_addr().expect("sender address"));
        assert_eq!(destination_ip, listener_addr.ip());
    }
}
