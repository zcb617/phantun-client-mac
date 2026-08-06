use async_trait::async_trait;
use bytes::Bytes;
use fake_tcp::packet::parse_ip_packet;
use fake_tcp::tun::TunDevice;
use log::warn;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::unix::AsyncFd;

const BPF_BUFFER_REQUESTED: u32 = 0x0008_0000;
const BPF_POLL_TIMEOUT_MILLIS: libc::c_int = 250;
const BPF_DLT_NULL: i32 = 0;
const BPF_DLT_EN10MB: i32 = 1;
const BPF_DLT_RAW: i32 = 12;
const BIOCSSEESENT: libc::c_ulong = 0x8004_4277;
const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
const BPF_CAPLEN_OFFSET: usize = std::mem::offset_of!(libc::bpf_hdr, bh_caplen);
const BPF_HDRLEN_OFFSET: usize = std::mem::offset_of!(libc::bpf_hdr, bh_hdrlen);
const BPF_HEADER_MIN_SIZE: usize = BPF_HDRLEN_OFFSET + size_of::<libc::c_ushort>();
const CLEANUP_MODE_ENV: &str = "PHANTUN_CLIENT_MAC_CLEANUP_MODE";
const CLEANUP_ANCHOR_ENV: &str = "PHANTUN_CLIENT_MAC_CLEANUP_ANCHOR";
const CLEANUP_TOKEN_ENV: &str = "PHANTUN_CLIENT_MAC_CLEANUP_TOKEN";
const CLEANUP_PARENT_PID_ENV: &str = "PHANTUN_CLIENT_MAC_CLEANUP_PARENT_PID";

#[repr(C)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: libc::c_uint,
    bf_insns: *mut BpfInsn,
}

struct CompiledBpfProgram {
    raw: BpfProgram,
}

impl Drop for CompiledBpfProgram {
    fn drop(&mut self) {
        unsafe { pcap_freecode(&mut self.raw) };
    }
}

#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_compile_nopcap(
        snaplen: libc::c_int,
        linktype: libc::c_int,
        program: *mut BpfProgram,
        expression: *const libc::c_char,
        optimize: libc::c_int,
        netmask: u32,
    ) -> libc::c_int;
    fn pcap_freecode(program: *mut BpfProgram);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkType {
    Null,
    Ethernet,
    Raw,
}

impl LinkType {
    fn from_dlt(value: i32) -> io::Result<Self> {
        match value {
            BPF_DLT_NULL => Ok(Self::Null),
            BPF_DLT_EN10MB => Ok(Self::Ethernet),
            BPF_DLT_RAW => Ok(Self::Raw),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported macOS BPF datalink type {value}"),
            )),
        }
    }

    fn dlt(self) -> i32 {
        match self {
            Self::Null => BPF_DLT_NULL,
            Self::Ethernet => BPF_DLT_EN10MB,
            Self::Raw => BPF_DLT_RAW,
        }
    }
}

/// A macOS packet adapter with the same observable forwarding boundary as the
/// Windows WinDivert adapter: it sends the userspace TCP packets, receives only
/// TCP replies from the configured Phantun server, and keeps those replies away
/// from the operating system TCP stack.
pub struct MacPacketDevice {
    capture: BpfCapture,
    sender: RawPacketSender,
    _firewall: FirewallGuard,
    interface_name: String,
}

impl MacPacketDevice {
    pub fn new(remote_addr: SocketAddr, local_ipv6: Option<SocketAddrV6>) -> io::Result<Self> {
        let interface_name = route_interface(remote_addr.ip()).map_err(|error_value| {
            contextual_error("resolve the outbound interface", error_value)
        })?;
        let capture = BpfCapture::open(&interface_name, remote_addr)
            .map_err(|error_value| contextual_error("open the macOS BPF capture", error_value))?;
        let sender = RawPacketSender::new(remote_addr, local_ipv6)
            .map_err(|error_value| contextual_error("open the raw TCP sender", error_value))?;
        let firewall = FirewallGuard::install(remote_addr).map_err(|error_value| {
            contextual_error("install the temporary PF rule", error_value)
        })?;

        Ok(Self {
            capture,
            sender,
            _firewall: firewall,
            interface_name: format!("BPF/{interface_name}"),
        })
    }
}

fn contextual_error(context: &str, error_value: io::Error) -> io::Error {
    io::Error::new(error_value.kind(), format!("{context}: {error_value}"))
}

#[async_trait]
impl TunDevice for MacPacketDevice {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.capture.read_packet(buffer).await
    }

    async fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        self.sender.send(buffer).await
    }

    fn name(&self) -> String {
        self.interface_name.clone()
    }

    fn try_send(&self, buffer: &[u8]) -> io::Result<()> {
        self.sender.try_send(buffer)
    }
}

struct BpfCapture {
    fd: Arc<OwnedFd>,
    buffer_len: usize,
    link_type: LinkType,
    remote_addr: SocketAddr,
    pending: Mutex<VecDeque<Vec<u8>>>,
}

impl BpfCapture {
    fn open(interface_name: &str, remote_addr: SocketAddr) -> io::Result<Self> {
        let fd = open_bpf_device()
            .map_err(|error_value| contextual_error("open /dev/bpf", error_value))?;
        configure_bpf(fd, interface_name, remote_addr)
            .map_err(|error_value| contextual_error("configure /dev/bpf", error_value))
    }

    async fn read_packet(&self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(size) = self.copy_pending_packet(output)? {
                return Ok(size);
            }

            let fd = Arc::clone(&self.fd);
            let buffer_len = self.buffer_len;
            let records =
                tokio::task::spawn_blocking(move || read_bpf_records(fd.as_ref(), buffer_len))
                    .await
                    .map_err(|error_value| {
                        io::Error::other(format!("macOS BPF reader task failed: {error_value}"))
                    })??;

            let Some(records) = records else {
                continue;
            };
            let packets = Self::decode_records(&records, self.link_type, self.remote_addr)?;
            if !packets.is_empty() {
                self.pending
                    .lock()
                    .map_err(|_| io::Error::other("macOS BPF queue lock poisoned"))?
                    .extend(packets);
            }
        }
    }

    fn copy_pending_packet(&self, output: &mut [u8]) -> io::Result<Option<usize>> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("macOS BPF queue lock poisoned"))?;
        while let Some(packet) = pending.pop_front() {
            if packet.len() > output.len() {
                warn!(
                    "Dropping {}-byte packet because the fake-TCP receive buffer is {} bytes",
                    packet.len(),
                    output.len()
                );
                continue;
            }
            output[..packet.len()].copy_from_slice(&packet);
            return Ok(Some(packet.len()));
        }
        Ok(None)
    }

    fn decode_records(
        records: &[u8],
        link_type: LinkType,
        remote_addr: SocketAddr,
    ) -> io::Result<Vec<Vec<u8>>> {
        let mut offset = 0;
        let mut packets = Vec::new();

        while offset < records.len() {
            if records.len() - offset < BPF_HEADER_MIN_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated macOS BPF record header",
                ));
            }
            let header_len = u16::from_ne_bytes(
                records[offset + BPF_HDRLEN_OFFSET..offset + BPF_HEADER_MIN_SIZE]
                    .try_into()
                    .expect("fixed BPF header length"),
            ) as usize;
            let caplen = u32::from_ne_bytes(
                records[offset + BPF_CAPLEN_OFFSET..offset + BPF_CAPLEN_OFFSET + 4]
                    .try_into()
                    .expect("fixed BPF capture length"),
            ) as usize;
            let packet_start = offset + header_len;
            let packet_end = packet_start + caplen;
            if header_len < BPF_HEADER_MIN_SIZE
                || packet_start > records.len()
                || packet_end > records.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid macOS BPF record boundaries",
                ));
            }

            if let Some(packet) =
                packet_from_link_frame(link_type, &records[packet_start..packet_end])
                && is_expected_remote_packet(packet, remote_addr)
            {
                packets.push(packet.to_vec());
            }

            let next_offset = bpf_word_align(packet_end);
            if next_offset <= offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid macOS BPF record alignment",
                ));
            }
            if next_offset > records.len() {
                if packet_end == records.len() {
                    break;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid macOS BPF record alignment",
                ));
            }
            offset = next_offset;
        }

        Ok(packets)
    }
}

fn open_bpf_device() -> io::Result<OwnedFd> {
    let mut last_error = None;
    for index in 0..=255 {
        let path = CString::new(format!("/dev/bpf{index}")).expect("BPF device path has no NUL");
        let raw_fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if raw_fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) });
        }

        let error_value = io::Error::last_os_error();
        if error_value.raw_os_error() != Some(libc::EBUSY) {
            return Err(error_value);
        }
        last_error = Some(error_value);
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no macOS BPF capture device is available",
        )
    }))
}

fn configure_bpf(
    fd: OwnedFd,
    interface_name: &str,
    remote_addr: SocketAddr,
) -> io::Result<BpfCapture> {
    if interface_name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("network interface name is too long: {interface_name}"),
        ));
    }

    let mut buffer_len = BPF_BUFFER_REQUESTED;
    ioctl_with_mut(&fd, libc::BIOCSBLEN, &mut buffer_len)
        .map_err(|error_value| contextual_error("BIOCSBLEN", error_value))?;

    let mut interface: libc::ifreq = unsafe { zeroed() };
    for (slot, byte) in interface
        .ifr_name
        .iter_mut()
        .zip(interface_name.as_bytes().iter().copied())
    {
        *slot = byte as libc::c_char;
    }
    ioctl_with_mut(&fd, libc::BIOCSETIF, &mut interface)
        .map_err(|error_value| contextual_error("BIOCSETIF", error_value))?;

    let mut immediate: libc::c_uint = 1;
    ioctl_with_mut(&fd, libc::BIOCIMMEDIATE, &mut immediate)
        .map_err(|error_value| contextual_error("BIOCIMMEDIATE", error_value))?;
    // Keep locally generated frames visible as well. The BPF program already
    // selects only packets sourced by the configured Phantun server, which is
    // necessary when that server is reached through loopback.
    let mut see_sent: libc::c_uint = 1;
    ioctl_with_mut(&fd, BIOCSSEESENT, &mut see_sent)
        .map_err(|error_value| contextual_error("BIOCSSEESENT", error_value))?;

    let mut dlt: libc::c_uint = 0;
    ioctl_with_mut(&fd, libc::BIOCGDLT, &mut dlt)
        .map_err(|error_value| contextual_error("BIOCGDLT", error_value))?;
    let link_type = LinkType::from_dlt(dlt as i32)?;
    install_bpf_filter(&fd, link_type, remote_addr)
        .map_err(|error_value| contextual_error("install BPF filter", error_value))?;

    let mut actual_buffer_len: libc::c_uint = 0;
    ioctl_with_mut(&fd, libc::BIOCGBLEN, &mut actual_buffer_len)
        .map_err(|error_value| contextual_error("BIOCGBLEN", error_value))?;
    if actual_buffer_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS BPF returned an empty receive buffer",
        ));
    }

    Ok(BpfCapture {
        // Darwin's BPF character device does not support registration with
        // kqueue on current macOS releases. Keep the descriptor nonblocking
        // and poll it in the dedicated blocking pool instead.
        fd: Arc::new(fd),
        buffer_len: actual_buffer_len as usize,
        link_type,
        remote_addr,
        pending: Mutex::new(VecDeque::new()),
    })
}

fn read_bpf_records(fd: &OwnedFd, buffer_len: usize) -> io::Result<Option<Vec<u8>>> {
    let mut poll_fd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = loop {
        let value = unsafe { libc::poll(&mut poll_fd, 1, BPF_POLL_TIMEOUT_MILLIS) };
        if value >= 0 {
            break value;
        }
        let error_value = io::Error::last_os_error();
        if error_value.kind() != io::ErrorKind::Interrupted {
            return Err(error_value);
        }
    };
    if ready == 0 {
        return Ok(None);
    }

    let error_events = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
    if poll_fd.revents & error_events != 0 {
        return Err(io::Error::other(format!(
            "macOS BPF poll returned error events: 0x{:x}",
            poll_fd.revents
        )));
    }
    if poll_fd.revents & libc::POLLIN == 0 {
        return Ok(None);
    }

    let mut records = vec![0_u8; buffer_len];
    let size = unsafe { libc::read(fd.as_raw_fd(), records.as_mut_ptr().cast(), records.len()) };
    if size < 0 {
        let error_value = io::Error::last_os_error();
        return if error_value.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error_value)
        };
    }
    if size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "macOS BPF device closed",
        ));
    }
    records.truncate(size as usize);
    Ok(Some(records))
}

fn ioctl_with_mut<T>(fd: &OwnedFd, request: libc::c_ulong, value: &mut T) -> io::Result<()> {
    if unsafe { libc::ioctl(fd.as_raw_fd(), request, value) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn install_bpf_filter(
    fd: &OwnedFd,
    link_type: LinkType,
    remote_addr: SocketAddr,
) -> io::Result<()> {
    let program = compile_bpf_filter(link_type, remote_addr)?;
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCSETF, &program.raw) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn compile_bpf_filter(
    link_type: LinkType,
    remote_addr: SocketAddr,
) -> io::Result<CompiledBpfProgram> {
    let expression = CString::new(format!(
        "tcp and src host {} and src port {}",
        remote_addr.ip(),
        remote_addr.port()
    ))
    .expect("socket address cannot contain NUL");
    let mut program = BpfProgram {
        bf_len: 0,
        bf_insns: std::ptr::null_mut(),
    };
    let compilation = unsafe {
        pcap_compile_nopcap(
            65_535,
            link_type.dlt(),
            &mut program,
            expression.as_ptr(),
            1,
            PCAP_NETMASK_UNKNOWN,
        )
    };
    if compilation != 0 {
        return Err(io::Error::other(
            "unable to compile the macOS BPF filter for the Phantun remote",
        ));
    }
    Ok(CompiledBpfProgram { raw: program })
}

fn bpf_word_align(value: usize) -> usize {
    (value + 3) & !3
}

fn packet_from_link_frame(link_type: LinkType, frame: &[u8]) -> Option<&[u8]> {
    let packet = match link_type {
        LinkType::Raw => frame,
        LinkType::Null => {
            if frame.len() < 4 {
                return None;
            }
            let family = u32::from_ne_bytes(frame[..4].try_into().expect("fixed length"));
            if family != libc::AF_INET as u32 && family != libc::AF_INET6 as u32 {
                return None;
            }
            &frame[4..]
        }
        LinkType::Ethernet => ethernet_network_packet(frame)?,
    };
    normalize_ip_packet(packet)
}

fn ethernet_network_packet(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }

    let mut network_offset = 14;
    let mut ether_type = u16::from_be_bytes(frame[12..14].try_into().expect("fixed length"));
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        if frame.len() < network_offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes(
            frame[network_offset + 2..network_offset + 4]
                .try_into()
                .expect("fixed length"),
        );
        network_offset += 4;
    }

    match ether_type {
        0x0800 | 0x86dd => Some(&frame[network_offset..]),
        _ => None,
    }
}

fn normalize_ip_packet(packet: &[u8]) -> Option<&[u8]> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            if packet.len() < 40 || packet[9] != libc::IPPROTO_TCP as u8 || packet[0] & 0x0f != 5 {
                return None;
            }
            let total_len =
                u16::from_be_bytes(packet[2..4].try_into().expect("fixed length")) as usize;
            let fragment_offset =
                u16::from_be_bytes(packet[6..8].try_into().expect("fixed length")) & 0x1fff;
            if total_len < 40 || total_len > packet.len() || fragment_offset != 0 {
                return None;
            }
            Some(&packet[..total_len])
        }
        Some(6) => {
            if packet.len() < 60 || packet[6] != libc::IPPROTO_TCP as u8 {
                return None;
            }
            let payload_len =
                u16::from_be_bytes(packet[4..6].try_into().expect("fixed length")) as usize;
            let total_len = 40 + payload_len;
            if payload_len < 20 || total_len > packet.len() {
                return None;
            }
            Some(&packet[..total_len])
        }
        _ => None,
    }
}

fn is_expected_remote_packet(packet: &[u8], remote_addr: SocketAddr) -> bool {
    let packet = Bytes::copy_from_slice(packet);
    let Some((ip_packet, tcp_packet)) = parse_ip_packet(&packet) else {
        return false;
    };
    SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source()) == remote_addr
}

enum RawPacketSender {
    Ipv4 {
        fd: AsyncFd<OwnedFd>,
        remote: libc::sockaddr_in,
    },
    Ipv6 {
        fd: AsyncFd<OwnedFd>,
        remote: libc::sockaddr_in6,
    },
}

impl RawPacketSender {
    fn new(remote_addr: SocketAddr, local_ipv6: Option<SocketAddrV6>) -> io::Result<Self> {
        match remote_addr {
            SocketAddr::V4(remote) => {
                let fd = open_raw_socket(libc::AF_INET, libc::IPPROTO_RAW)?;
                let include_header: libc::c_int = 1;
                if unsafe {
                    libc::setsockopt(
                        fd.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_HDRINCL,
                        (&include_header as *const libc::c_int).cast(),
                        size_of::<libc::c_int>() as libc::socklen_t,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self::Ipv4 {
                    fd: AsyncFd::new(fd)?,
                    remote: raw_destination_v4(remote),
                })
            }
            SocketAddr::V6(remote) => {
                let local = local_ipv6.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "no local IPv6 address is available for the configured remote",
                    )
                })?;
                let fd = open_raw_socket(libc::AF_INET6, libc::IPPROTO_TCP)?;
                let local_address = sockaddr_v6(SocketAddrV6::new(
                    *local.ip(),
                    0,
                    local.flowinfo(),
                    local.scope_id(),
                ));
                if unsafe {
                    libc::bind(
                        fd.as_raw_fd(),
                        (&local_address as *const libc::sockaddr_in6).cast(),
                        size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self::Ipv6 {
                    fd: AsyncFd::new(fd)?,
                    remote: raw_destination_v6(remote),
                })
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        match self {
            Self::Ipv4 { fd, remote } => {
                wait_writable(fd, |raw_fd| send_ipv4_packet(raw_fd, remote, packet)).await
            }
            Self::Ipv6 { fd, remote } => {
                wait_writable(fd, |raw_fd| send_ipv6_packet(raw_fd, remote, packet)).await
            }
        }
    }

    fn try_send(&self, packet: &[u8]) -> io::Result<()> {
        match self {
            Self::Ipv4 { fd, remote } => send_ipv4_packet(fd.get_ref().as_raw_fd(), remote, packet),
            Self::Ipv6 { fd, remote } => send_ipv6_packet(fd.get_ref().as_raw_fd(), remote, packet),
        }
        .map(|_| ())
    }
}

fn open_raw_socket(domain: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    let raw_fd = unsafe { libc::socket(domain, libc::SOCK_RAW, protocol) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    set_nonblocking(fd.as_raw_fd())?;
    Ok(fd)
}

fn set_nonblocking(raw_fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

async fn wait_writable<F>(fd: &AsyncFd<OwnedFd>, mut write_packet: F) -> io::Result<usize>
where
    F: FnMut(RawFd) -> io::Result<usize>,
{
    loop {
        let mut readiness = fd.writable().await?;
        match readiness.try_io(|inner| write_packet(inner.get_ref().as_raw_fd())) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

fn send_ipv4_packet(raw_fd: RawFd, remote: &libc::sockaddr_in, packet: &[u8]) -> io::Result<usize> {
    if !matches!(packet.first(), Some(byte) if byte >> 4 == 4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv4 raw socket received a non-IPv4 fake-TCP packet",
        ));
    }
    let packet = macos_raw_ipv4_packet(packet)?;
    send_to(raw_fd, &packet, remote, size_of::<libc::sockaddr_in>())
}

fn macos_raw_ipv4_packet(packet: &[u8]) -> io::Result<Vec<u8>> {
    if packet.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv4 fake-TCP packet is shorter than its IP header",
        ));
    }
    let header_len = (packet[0] as usize & 0x0f) * 4;
    let total_len = u16::from_be_bytes(packet[2..4].try_into().expect("fixed length"));
    if header_len < 20 || header_len > packet.len() || total_len as usize != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv4 fake-TCP packet has an invalid total length",
        ));
    }

    let mut macos_packet = packet.to_vec();
    // Darwin's IP_HDRINCL path reads ip_len and ip_off in host byte order
    // before it serializes the header on output. fake-tcp creates a normal
    // wire-format IPv4 packet, so convert those fields for the raw socket call.
    macos_packet[2..4].copy_from_slice(&total_len.to_ne_bytes());
    let fragment_offset = u16::from_be_bytes(packet[6..8].try_into().expect("fixed length"));
    macos_packet[6..8].copy_from_slice(&fragment_offset.to_ne_bytes());
    Ok(macos_packet)
}

fn send_ipv6_packet(
    raw_fd: RawFd,
    remote: &libc::sockaddr_in6,
    packet: &[u8],
) -> io::Result<usize> {
    let payload = ipv6_tcp_payload(packet)?;
    send_to(raw_fd, payload, remote, size_of::<libc::sockaddr_in6>()).map(|_| packet.len())
}

fn send_to<T>(raw_fd: RawFd, packet: &[u8], remote: &T, address_len: usize) -> io::Result<usize> {
    let size = unsafe {
        libc::sendto(
            raw_fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (remote as *const T).cast(),
            address_len as libc::socklen_t,
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short write to raw IP socket",
        ));
    }
    Ok(size as usize)
}

fn ipv6_tcp_payload(packet: &[u8]) -> io::Result<&[u8]> {
    if packet.len() < 60 || packet[0] >> 4 != 6 || packet[6] != libc::IPPROTO_TCP as u8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv6 raw socket received an invalid fake-TCP packet",
        ));
    }
    let payload_len = u16::from_be_bytes(packet[4..6].try_into().expect("fixed length")) as usize;
    if payload_len < 20 || payload_len + 40 != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPv6 fake-TCP packet has an invalid payload length",
        ));
    }
    Ok(&packet[40..])
}

fn sockaddr_v4(address: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn raw_destination_v4(address: SocketAddrV4) -> libc::sockaddr_in {
    let mut destination = sockaddr_v4(address);
    // The TCP port is carried in the supplied IP packet. BSD raw-IP sockets
    // require the sockaddr port to be zero; macOS rejects a nonzero value with
    // EINVAL before transmitting the packet.
    destination.sin_port = 0;
    destination
}

fn sockaddr_v6(address: SocketAddrV6) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: address.port().to_be(),
        sin6_flowinfo: address.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: address.ip().octets(),
        },
        sin6_scope_id: address.scope_id(),
    }
}

fn raw_destination_v6(address: SocketAddrV6) -> libc::sockaddr_in6 {
    let mut destination = sockaddr_v6(address);
    // Like IPv4 raw-IP sockets, the TCP port belongs to the packet payload.
    destination.sin6_port = 0;
    destination
}

struct FirewallGuard {
    anchor: String,
    token: String,
    cleanup_helper: Option<Child>,
}

impl FirewallGuard {
    fn install(remote_addr: SocketAddr) -> io::Result<Self> {
        let token = enable_packet_filter()?;
        if let Err(error_value) = ensure_macos_anchor() {
            let _ = release_packet_filter(&token);
            return Err(error_value);
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let anchor = format!("com.apple/phantun-client-{}-{nonce}", std::process::id());
        if let Err(error_value) = load_packet_filter_rule(&anchor, remote_addr) {
            let _ = release_packet_filter(&token);
            return Err(error_value);
        }
        let cleanup_helper = match spawn_cleanup_helper(&anchor, &token) {
            Ok(helper) => helper,
            Err(error_value) => {
                let _ = clear_packet_filter_rule(&anchor);
                let _ = release_packet_filter(&token);
                return Err(error_value);
            }
        };
        Ok(Self {
            anchor,
            token,
            cleanup_helper: Some(cleanup_helper),
        })
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if let Some(mut cleanup_helper) = self.cleanup_helper.take() {
            let _ = cleanup_helper.kill();
            let _ = cleanup_helper.wait();
        }
        if let Err(error_value) = clear_packet_filter_rule(&self.anchor) {
            warn!(
                "Unable to clear temporary Phantun packet-filter rule {}: {}",
                self.anchor, error_value
            );
        }
        if let Err(error_value) = release_packet_filter(&self.token) {
            warn!(
                "Unable to release temporary Phantun packet-filter reference: {}",
                error_value
            );
        }
    }
}

/// Runs only in the private watchdog process started by [`FirewallGuard`].
/// The watchdog releases the temporary rule and PF reference if the main
/// process is killed before Rust destructors can run.
pub fn run_cleanup_helper_if_requested() -> io::Result<bool> {
    if std::env::var_os(CLEANUP_MODE_ENV).is_none() {
        return Ok(false);
    }

    detach_cleanup_helper_from_terminal_signals();

    let anchor = required_cleanup_environment(CLEANUP_ANCHOR_ENV)?;
    let token = required_cleanup_environment(CLEANUP_TOKEN_ENV)?;
    let parent_pid = required_cleanup_environment(CLEANUP_PARENT_PID_ENV)?
        .parse::<libc::pid_t>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Phantun cleanup parent process identifier",
            )
        })?;
    if parent_pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Phantun cleanup parent process identifier",
        ));
    }

    while process_is_alive(parent_pid) {
        std::thread::sleep(Duration::from_millis(250));
    }
    let _ = clear_packet_filter_rule(&anchor);
    let _ = release_packet_filter(&token);
    Ok(true)
}

fn detach_cleanup_helper_from_terminal_signals() {
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
        libc::setsid();
    }
}

fn required_cleanup_environment(name: &str) -> io::Result<String> {
    std::env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing internal Phantun cleanup value {name}"),
        )
    })
}

fn process_is_alive(process_id: libc::pid_t) -> bool {
    if unsafe { libc::kill(process_id, 0) } == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn spawn_cleanup_helper(anchor: &str, token: &str) -> io::Result<Child> {
    let executable = std::env::current_exe()?;
    Command::new(executable)
        .env(CLEANUP_MODE_ENV, "1")
        .env(CLEANUP_ANCHOR_ENV, anchor)
        .env(CLEANUP_TOKEN_ENV, token)
        .env(CLEANUP_PARENT_PID_ENV, std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn enable_packet_filter() -> io::Result<String> {
    let output = run_pfctl(["-E"])?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim() == "Token").then(|| value.trim().to_owned())
        })
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            io::Error::other("pfctl enabled packet filtering but returned no reference token")
        })
}

fn ensure_macos_anchor() -> io::Result<()> {
    let output = run_pfctl(["-s", "rules"])?;
    let rules = String::from_utf8_lossy(&output.stdout);
    if macos_anchor_available(&rules) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the active PF ruleset has no macOS com.apple anchor; refusing to start without reliable packet interception",
    ))
}

fn macos_anchor_available(rules: &str) -> bool {
    rules.lines().any(|line| {
        let line = line.trim();
        line.contains("anchor") && line.contains("com.apple/*")
    })
}

fn load_packet_filter_rule(anchor: &str, remote_addr: SocketAddr) -> io::Result<()> {
    let mut child = Command::new("/sbin/pfctl")
        .args(["-a", anchor, "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let rule = packet_filter_rule(remote_addr);
    std::io::Write::write_all(
        child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("pfctl stdin is unavailable"))?,
        rule.as_bytes(),
    )?;
    let output = child.wait_with_output()?;
    checked_pfctl_output(output).map(|_| ())
}

fn clear_packet_filter_rule(anchor: &str) -> io::Result<()> {
    run_pfctl(["-a", anchor, "-F", "rules"]).map(|_| ())
}

fn release_packet_filter(token: &str) -> io::Result<()> {
    run_pfctl(["-X", token]).map(|_| ())
}

fn run_pfctl<const N: usize>(arguments: [&str; N]) -> io::Result<std::process::Output> {
    checked_pfctl_output(Command::new("/sbin/pfctl").args(arguments).output()?)
}

fn checked_pfctl_output(output: std::process::Output) -> io::Result<std::process::Output> {
    if output.status.success() {
        return Ok(output);
    }
    let diagnostic = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        if diagnostic.is_empty() {
            "pfctl failed; run the client with administrator privileges".to_owned()
        } else {
            format!("pfctl failed: {diagnostic}")
        },
    ))
}

fn packet_filter_rule(remote_addr: SocketAddr) -> String {
    let family = if remote_addr.is_ipv4() {
        "inet"
    } else {
        "inet6"
    };
    format!(
        "block drop in quick {family} proto tcp from {} port {} to any\n",
        remote_addr.ip(),
        remote_addr.port()
    )
}

fn route_interface(remote_ip: IpAddr) -> io::Result<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", &remote_ip.to_string()])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "unable to resolve outbound interface for {remote_ip}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    parse_route_interface(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
        io::Error::other(format!(
            "route lookup did not report an interface for {remote_ip}"
        ))
    })
}

fn parse_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == "interface").then(|| value.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake_tcp::packet::build_tcp_packet;
    use pnet_packet::tcp::TcpFlags;

    fn remote() -> SocketAddr {
        "203.0.113.20:65009".parse().expect("valid test address")
    }

    fn raw_reply() -> Bytes {
        build_tcp_packet(
            remote(),
            "198.51.100.10:40000".parse().expect("valid test address"),
            0,
            1,
            TcpFlags::SYN | TcpFlags::ACK,
            None,
        )
    }

    #[test]
    fn ethernet_and_vlan_frames_preserve_the_ip_packet() {
        let raw = raw_reply();
        let mut ethernet = vec![0_u8; 14];
        ethernet[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
        ethernet.extend_from_slice(&[0, 1]);
        ethernet.extend_from_slice(&0x0800_u16.to_be_bytes());
        ethernet.extend_from_slice(&raw);

        assert_eq!(
            packet_from_link_frame(LinkType::Ethernet, &ethernet),
            Some(raw.as_ref())
        );
    }

    #[test]
    fn bpf_records_only_return_the_configured_remote() {
        let raw = raw_reply();
        let mut ethernet = vec![0_u8; 14];
        ethernet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        ethernet.extend_from_slice(&raw);

        let header_len = BPF_HEADER_MIN_SIZE;
        assert_eq!(
            header_len, 18,
            "Darwin BPF records use an 18-byte base header"
        );
        let mut records = vec![0_u8; header_len];
        records[8..12].copy_from_slice(&(ethernet.len() as u32).to_ne_bytes());
        records[12..16].copy_from_slice(&(ethernet.len() as u32).to_ne_bytes());
        records[16..18].copy_from_slice(&(header_len as u16).to_ne_bytes());
        records.extend_from_slice(&ethernet);
        records.resize(bpf_word_align(records.len()), 0);

        assert_eq!(
            BpfCapture::decode_records(&records, LinkType::Ethernet, remote())
                .expect("valid BPF record"),
            vec![raw.to_vec()]
        );
    }

    #[test]
    fn final_unpadded_bpf_record_is_accepted() {
        let raw = build_tcp_packet(
            remote(),
            "198.51.100.10:40000".parse().expect("valid test address"),
            1,
            1,
            TcpFlags::ACK,
            Some(b"x"),
        );
        let mut ethernet = vec![0_u8; 14];
        ethernet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        ethernet.extend_from_slice(&raw);

        let mut records = vec![0_u8; BPF_HEADER_MIN_SIZE];
        records[8..12].copy_from_slice(&(ethernet.len() as u32).to_ne_bytes());
        records[12..16].copy_from_slice(&(ethernet.len() as u32).to_ne_bytes());
        records[16..18].copy_from_slice(&(BPF_HEADER_MIN_SIZE as u16).to_ne_bytes());
        records.extend_from_slice(&ethernet);
        assert_ne!(
            records.len() % 4,
            0,
            "record deliberately has no tail padding"
        );

        assert_eq!(
            BpfCapture::decode_records(&records, LinkType::Ethernet, remote())
                .expect("final unpadded record is valid"),
            vec![raw.to_vec()]
        );
    }

    #[test]
    fn only_the_configured_remote_packet_is_accepted() {
        let raw = raw_reply();
        let unexpected = build_tcp_packet(
            "203.0.113.21:65009".parse().expect("valid test address"),
            "198.51.100.10:40000".parse().expect("valid test address"),
            0,
            1,
            TcpFlags::SYN | TcpFlags::ACK,
            None,
        );
        assert!(is_expected_remote_packet(&raw, remote()));
        assert!(!is_expected_remote_packet(&unexpected, remote()));
    }

    #[test]
    fn ipv6_raw_socket_only_receives_the_tcp_payload() {
        let packet = build_tcp_packet(
            "[2001:db8::10]:40000".parse().expect("valid test address"),
            "[2001:db8::20]:65009".parse().expect("valid test address"),
            1,
            2,
            TcpFlags::ACK,
            Some(b"payload"),
        );
        assert_eq!(
            ipv6_tcp_payload(&packet).expect("valid IPv6 packet"),
            &packet[40..]
        );
    }

    #[test]
    fn raw_ipv4_packet_uses_darwin_host_order_length() {
        let packet = build_tcp_packet(
            "192.0.2.10:40000".parse().expect("valid IPv4 address"),
            remote(),
            0,
            0,
            TcpFlags::SYN,
            None,
        );

        let prepared = macos_raw_ipv4_packet(&packet).expect("valid IPv4 packet");

        assert_eq!(
            u16::from_ne_bytes(prepared[2..4].try_into().expect("fixed length")),
            packet.len() as u16
        );
        assert_eq!(
            u16::from_ne_bytes(prepared[6..8].try_into().expect("fixed length")),
            u16::from_be_bytes(packet[6..8].try_into().expect("fixed length"))
        );
        assert_eq!(&prepared[4..6], &packet[4..6]);
        assert_eq!(&prepared[8..], &packet[8..]);
    }

    #[test]
    fn packet_filter_rule_is_limited_to_the_configured_remote() {
        assert_eq!(
            packet_filter_rule(remote()),
            "block drop in quick inet proto tcp from 203.0.113.20 port 65009 to any\n"
        );
    }

    #[test]
    fn route_output_extracts_the_selected_interface() {
        let output = "   route to: 203.0.113.20\n destination: default\n  interface: en0\n";
        assert_eq!(parse_route_interface(output), Some("en0".to_owned()));
    }

    #[test]
    fn bpf_filters_compile_for_supported_links_and_ip_families() {
        let ipv4: SocketAddr = "203.0.113.20:65009".parse().expect("valid IPv4 address");
        let ipv6: SocketAddr = "[2001:db8::20]:65009".parse().expect("valid IPv6 address");
        for (link_type, remote) in [
            (LinkType::Ethernet, ipv4),
            (LinkType::Null, ipv4),
            (LinkType::Raw, ipv6),
        ] {
            let program = compile_bpf_filter(link_type, remote).expect("filter must compile");
            assert!(program.raw.bf_len > 0);
            assert!(!program.raw.bf_insns.is_null());
        }
    }

    #[test]
    fn active_rules_must_expose_the_macos_anchor() {
        assert!(macos_anchor_available("anchor \"com.apple/*\" all"));
        assert!(!macos_anchor_available("anchor \"com.apple/custom\" all"));
        assert!(!macos_anchor_available("pass out all"));
    }
}
