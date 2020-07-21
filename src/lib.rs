use socket2::{Domain, SockAddr as SockAddr2, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SsdpProbeError {
    #[error("an IO error was encountered")]
    Io(#[from] std::io::Error),
    #[error("could convert address {:?}", .0)]
    AddressConversionError(SockAddr2),
    #[error("got ipv6 address {:?} but expected an ipv4 one", .0)]
    UnexpectedIpv4(Ipv4Addr),
    #[error("got ipv4 address {:?} but expected an ipv6 one", .0)]
    UnexpectedIpv6(Ipv6Addr),
}

pub fn ssdp_probe_v4(
    marker: &[u8],
    max_results: usize,
    max_duration: Duration,
) -> Result<Vec<Ipv4Addr>, SsdpProbeError> {
    ssdp_probe(
        marker,
        max_results,
        max_duration,
        SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 1900),
        SsdpMSearch {
            host: SocketAddr::new(IpAddr::from(Ipv4Addr::new(239, 255, 255, 250)), 1900),
            mx: 3,
            st: "upnp:rootdevice",
            extra_lines: "",
        },
        SocketAddr::new(IpAddr::from(Ipv4Addr::new(239, 255, 255, 250)), 1900),
        Domain::ipv4(),
    )
    .and_then(|results| {
        results
            .into_iter()
            .map(|it| match it {
                IpAddr::V4(address) => Ok(address),
                IpAddr::V6(address) => Err(SsdpProbeError::UnexpectedIpv6(address)),
            })
            .collect()
    })
}

pub fn ssdp_probe_v6(
    marker: &[u8],
    max_results: usize,
    max_duration: Duration,
) -> Result<Vec<Ipv6Addr>, SsdpProbeError> {
    ssdp_probe(
        marker,
        max_results,
        max_duration,
        SocketAddr::new(IpAddr::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 1900),
        SsdpMSearch {
            host: SocketAddr::new(
                IpAddr::from(Ipv6Addr::new(0xFF, 0x02, 0, 0, 0, 0, 0, 0xC)),
                1900,
            ),
            mx: 3,
            st: "upnp:rootdevice",
            extra_lines: "",
        },
        SocketAddr::new(
            IpAddr::from(Ipv6Addr::new(0xFF, 0x02, 0, 0, 0, 0, 0, 0xC)),
            1900,
        ),
        Domain::ipv6(),
    )
    .and_then(|results| {
        results
            .into_iter()
            .map(|it| match it {
                IpAddr::V4(address) => Err(SsdpProbeError::UnexpectedIpv4(address)),
                IpAddr::V6(address) => Ok(address),
            })
            .collect()
    })
}

pub struct SsdpMSearch<'a> {
    pub host: SocketAddr,
    pub mx: usize,
    pub st: &'a str,
    pub extra_lines: &'a str,
impl<'a> SsdpMSearch<'a> {
    pub fn get_payload(&self) -> Vec<u8> {
        format!(
            r#"M-SEARCH * HTTP/1.1
HOST: {}
MAN: "ssdp:discover"
MX: {}
ST: {}
{}

"#,
            self.host, self.mx, self.st, self.extra_lines
        )
        .into_bytes()
    }
}

pub fn ssdp_probe(
    marker: &[u8],
    max_results: usize,
    max_duration: Duration,
    mut bind_address: SocketAddr,
    mut m_search: SsdpMSearch,
    address: SocketAddr,
    domain: Domain,
) -> Result<Vec<IpAddr>, SsdpProbeError> {
    log::debug!(
        "Starting an SSDP probe on {:?} searching for '{}', stopping after {} results or {}s",
        address,
        String::from_utf8_lossy(marker),
        max_results,
        max_duration.as_secs_f32()
    );
    let socket = Socket::new(domain, Type::dgram(), None)?;
    socket.set_multicast_ttl_v4(4)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let bind_result = socket.bind(&SockAddr2::from(bind_address));

    if let Err(e) = &bind_result {
        if e.kind() == ErrorKind::AddrInUse {
            bind_address.set_port(0);
            socket.bind(&SockAddr2::from(bind_address))?;
        } else {
            bind_result?;
        }
    }

    m_search.host.set_port(bind_address.port());

    socket.send_to(&m_search.get_payload(), &SockAddr2::from(address))?;

    let mut result = vec![];
    let mut data = [0u8; 1024];

    let start = std::time::Instant::now();

    loop {
        match socket.recv_from(&mut data) {
            Ok((count, addr)) => {
                log::debug!(
                    "Received SSDP data from {:?}: {:?}",
                    addr,
                    String::from_utf8_lossy(&data[0..count])
                );
                if data[0..count].windows(marker.len()).any(|it| it == marker) {
                    let addr = addr
                        .as_std()
                        .ok_or_else(|| SsdpProbeError::AddressConversionError(addr))?
                        .ip();

                    if result.iter().any(|it| it == &addr) {
                        log::debug!("Not adding {:?} to SSDP as it was already added", addr);
                    } else {
                        log::debug!("Adding {:?} to SSDP probe results", addr);
                        result.push(addr);
                    }
                }
                if result.len() >= max_results {
                    break;
                }
            }
            Err(e) => {
                if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock {
                    if start.elapsed() > max_duration {
                        log::debug!("SSDP max duration elapsed, returning");
                        break;
                    }
                } else {
                    return Err(SsdpProbeError::from(e));
                }
            }
        }
    }
    log::debug!("SSDP probe finished, results: {:?}", result);
    Ok(result)
}
