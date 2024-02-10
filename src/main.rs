// TODO - Use ef_vi
#[allow(dead_code)]
mod error;
mod tcp;

use {
    error::Error,
    etherparse::{Ipv4HeaderSlice, TcpHeaderSlice},
    hashbrown::{hash_map::Entry, HashMap},
    std::net::Ipv4Addr,
    tcp::{State, TransmissionControlBlock},
    tun_tap::{Iface, Mode},
};

pub const MTU: usize = 1500;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Socket {
    pub address: Ipv4Addr,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Connection {
    local: Socket,
    remote: Socket,
}

/// RFC9293 - 3.10.7.  SEGMENT ARRIVES
/// Listen to remote connection requets coming in the nic.
fn listen_remote(
    nic: &mut Iface,
    buf: &mut [u8],
    connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<(), Error> {
    let Ok(nbytes) = nic.recv(buf) else {
        return Ok(());
    };
    // 3.10.7.  SEGMENT ARRIVES
    if let Ok(ip_header) = Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
        if ip_header.protocol() != tcp::PROTOCOL {
            return Ok(());
        }

        let ip_header_size = ip_header.slice().len();
        match TcpHeaderSlice::from_slice(&buf[ip_header_size..nbytes]) {
            Ok(tcp_header) => {
                let data_offset = ip_header_size + tcp_header.slice().len();
                let connection = Connection {
                    local: Socket {
                        address: ip_header.destination_addr(),
                        port: tcp_header.destination_port(),
                    },
                    remote: Socket {
                        address: ip_header.source_addr(),
                        port: tcp_header.source_port(),
                    },
                };
                match connections.entry(connection) {
                    Entry::Occupied(mut entry) => {
                        let tcb = entry.get_mut();
                        if let Err(err) =
                            tcb.on_segment(nic, ip_header, tcp_header, &buf[data_offset..nbytes])
                        {
                            match err {
                                Error::ConnectionRefused | Error::ConnectionReset => {
                                    entry.remove_entry();
                                }
                                err => {
                                    eprintln!("{err}");
                                }
                            }
                        }
                    }
                    Entry::Vacant(_entry) => {
                        // 3.10.7.1.  CLOSED STATE
                        // Simply ignore it for now
                    }
                }
            }
            Err(e) => {
                eprintln!("Ignoring weird TCP packet {e:?}");
            }
        }
    }
    Ok(())
}

/// Create a passive connection, we want to listen to incoming connections.
pub fn listen(
    local: Socket,
    remote: Socket,
    connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<(), Error> {
    match connections.entry(Connection { local, remote }) {
        // Equivalent to the CLOSED state
        Entry::Vacant(entry) => {
            if let Ok(tcb) = TransmissionControlBlock::listen(local, remote) {
                entry.insert(tcb);
            }
        }
        Entry::Occupied(_) => {
            return Err(Error::ConnectionAlreadyExists);
        }
    }
    Ok(())
}

/// Create a active connection, we want to initate a connection.
pub fn connect(
    nic: &mut Iface,
    local: Socket,
    remote: Socket,
    data: &[u8],
    connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<(), Error> {
    match connections.entry(Connection { local, remote }) {
        // Equivalent to the CLOSED state
        Entry::Vacant(entry) => {
            if let Ok(tcb) = TransmissionControlBlock::create(nic, local, remote, false, data) {
                entry.insert(tcb);
            }
        }
        Entry::Occupied(mut entry) => {
            let tcb = entry.get_mut();
            tcb.open(nic, local, remote, false, data)?;
        }
    }
    Ok(())
}

// TODO - 3.10.2.  SEND Call
pub fn send(
    _nic: &mut Iface,
    _local: Socket,
    _remote: Socket,
    _data: &[u8],
    _connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<(), Error> {
    unimplemented!();
}

// TODO - 3.10.3.  RECEIVE Call
pub fn receive(
    _nic: &mut Iface,
    _local: Socket,
    _remote: Socket,
    _data: &[u8],
    _connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<(), Error> {
    unimplemented!();
}

// TODO - 3.10.4.  CLOSE Call
pub fn close(
    _nic: &mut Iface,
    _local: Socket,
    _remote: Socket,
    _data: &[u8],
    _connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<(), Error> {
    unimplemented!();
}

// TODO - 3.10.5.  ABORT Call
pub fn abort(
    _nic: &mut Iface,
    _local: Socket,
    _remote: Socket,
    _data: &[u8],
    _connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<(), Error> {
    unimplemented!();
}

// 3.10.6.  STATUS Call
pub fn status(
    local: Socket,
    remote: Socket,
    connections: &mut HashMap<Connection, TransmissionControlBlock>,
) -> Result<State, Error> {
    match connections.entry(Connection { local, remote }) {
        Entry::Vacant(_) => Err(Error::ConnectionDoesNotExit),
        Entry::Occupied(entry) => {
            let tcb = entry.get();
            Ok(tcb.state())
        }
    }
}

fn main() -> Result<(), Error> {
    let mut connections: HashMap<Connection, tcp::TransmissionControlBlock> = HashMap::default();
    let mut nic = Iface::without_packet_info("tun0", Mode::Tun)?;
    let mut buf = [0u8; MTU];
    let (local, remote) = (
        Socket {
            address: Ipv4Addr::new(192, 168, 0, 2),
            port: 5335,
        },
        Socket {
            address: Ipv4Addr::new(192, 168, 0, 1),
            port: 3456,
        },
    );
    if let Err(err) = listen(local, remote, &mut connections) {
        eprintln!("Error: {err}");
    }
    println!("Listening on {local:?}");
    loop {
        listen_remote(&mut nic, &mut buf, &mut connections)?;
        // TODO - Listen for local events
    }
}

// TODO - Test against proven TCP implementation
//      - Try sending segments out of order
#[cfg(test)]
mod tests {
    use {
        super::{tcp, Connection, Socket, State},
        hashbrown::{hash_map::Entry, HashMap},
        std::net::Ipv4Addr,
    };

    /// Create a [TransmissionControlBlock] with default values and with State::Listen.
    /// If the TCB already exists, assert that an error is returned.
    #[test]
    fn listen() {
        let mut connections: HashMap<Connection, tcp::TransmissionControlBlock> =
            HashMap::default();
        let (local, remote) = (
            Socket {
                address: Ipv4Addr::new(192, 168, 0, 2),
                port: 5335,
            },
            Socket {
                address: Ipv4Addr::new(192, 168, 0, 1),
                port: 3456,
            },
        );
        assert!(super::listen(local, remote, &mut connections).is_ok());
        match connections.entry(Connection { local, remote }) {
            Entry::Vacant(_) => {
                panic!("TransmissionControlBlock exists");
            }
            Entry::Occupied(entry) => {
                let tcb = entry.get();
                assert_eq!(tcb.state(), State::Listen);
            }
        }
        // TCB already exists.
        assert!(super::listen(local, remote, &mut connections).is_err());
    }
}
