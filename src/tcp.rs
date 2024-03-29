use {
    super::{error::Error, Socket, MTU},
    etherparse::{
        IpTrafficClass, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice, TcpOptionElement,
    },
    std::{
        fs::File,
        io::{self, BufWriter, Write},
    },
    tun_tap::Iface,
};

pub const PROTOCOL: u8 = 0x06;
/// From RFC793 TCP/Lower-Level Interface
/// Time to Live = one minute, or 00111100 (60).
const TTL: u8 = 60;

/// NOTE - RFC9293 - It is RECOMMENDED that implementations will
/// reserve 32-bit fields for the send and receive window sizes in the
/// connection record and do all window computations with 32 bits (REC-
/// 1).
type Window = u16;

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum State {
    /// Represents waiting for a connection request from any remote TCP peer and port.
    Listen,
    /// Represents waiting for a matching connection request
    /// after having sent a connection request.
    SynSent,
    /// Represents waiting for a confirming connection request acknowledgment
    /// after having both received and sent a connection request.
    SynReceived,
    /// Represents an open connection, data received can be delivered to the user.
    /// The normal state for the data transfer phase of the connection.
    Established,
    /// Represents waiting for a connection termination request from the remote TCP peer,
    /// or an acknowledgment of the connection termination request previously sent.
    FinWait1,
    /// Represents waiting for a connection termination request from the remote TCP peer.
    FinWait2,
    /// Represents waiting for a connection termination request from the local user.
    CloseWait,
    /// Represents waiting for a connection termination request acknowledgment from the remote TCP peer.
    Closing,
    /// Represents waiting for an acknowledgment of the connection termination request previously sent
    /// to the remote TCP peer (this termination request sent to the remote TCP peer already included
    /// an acknowledgment of the termination request sent from the remote TCP peer).
    LastAck,
    /// Represents waiting for enough time to pass to be sure the remote TCP peer received the acknowledgment
    /// of its connection termination request and to avoid new connections being impacted by delayed segments
    /// from previous connections.
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            Self::Listen | Self::SynSent | Self::SynReceived => false,
            Self::Established
            | Self::FinWait1
            | Self::FinWait2
            | Self::CloseWait
            | Self::Closing
            | Self::LastAck
            | Self::TimeWait => true,
        }
    }
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
/// The following diagrams may help to relate some of these variables to
/// the sequence space.
///
/// Send Sequence Space
///
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
///
#[derive(Debug)]
#[allow(dead_code)]
struct SendSequenceSpace {
    /// Send unacknowledged
    una: u32,
    /// Send next
    nxt: u32,
    /// Send window
    wnd: Window,
    /// Send urgent pointer
    up: bool,
    /// Segment sequence number used for last window update
    wl1: u32,
    /// Segment acknowledgment number used for last window update
    wl2: u32,
    /// Initial send sequence number
    iss: u32,
}

impl Default for SendSequenceSpace {
    fn default() -> Self {
        let iss = 0;
        Self {
            iss,
            una: iss,
            nxt: iss + 1,
            wnd: u16::MAX,
            up: false,
            wl1: 0,
            wl2: 0,
        }
    }
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// Receive Sequence Space
///
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
#[derive(Debug)]
#[allow(dead_code)]
struct RecvSequenceSpace {
    /// Receive next
    nxt: u32,
    /// Receive window
    wnd: Window,
    /// Receive urgent pointer
    up: bool,
    /// Initial receive sequence number
    irs: u32,
}

impl Default for RecvSequenceSpace {
    fn default() -> Self {
        Self {
            nxt: 0,
            wnd: u16::MAX,
            up: false,
            irs: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InitialState {
    /// Connection was created from a call to [TransmissionControlBlock::listen](TransmissionControlBlock::listen).
    Passive,
    /// Connection was created from a call to [TransmissionControlBlock::open](TransmissionControlBlock::open).
    Active,
}

#[derive(Debug)]
pub struct TransmissionControlBlock {
    /// Address and port of this instance
    local: Socket,
    /// Address and port of the remote instance
    remote: Socket,
    /// State of the connection
    state: State,
    /// Send sequence space
    snd: SendSequenceSpace,
    /// Receive sequence space
    rcv: RecvSequenceSpace,
    /// State from which the [TransmissionControlBlock](TransmissionControlBlock) was created.
    initial_state: InitialState,
    // TODO - Temp
    buffer: BufWriter<File>,
}

impl TransmissionControlBlock {
    pub fn state(&self) -> State {
        self.state
    }

    fn get_ip_header(&self, tcp_header_len: u16) -> Ipv4Header {
        Ipv4Header::new(
            tcp_header_len,
            TTL,
            IpTrafficClass::Tcp,
            self.local.address.octets(),
            self.remote.address.octets(),
        )
    }

    fn get_tcp_header(&self, sequence_number: u32, window: u16) -> TcpHeader {
        TcpHeader::new(self.local.port, self.remote.port, sequence_number, window)
    }

    fn write(
        &mut self,
        nic: &mut Iface,
        tcp_header: &mut TcpHeader,
        ip_header: &mut Ipv4Header,
        data: &[u8],
    ) -> io::Result<()> {
        // TODO - data can be > buf, handle backpressure/send queue.
        let metadata = ip_header.header_len() + tcp_header.header_len() as usize;
        let mss = MTU - metadata;
        let payload_size = std::cmp::min(mss, data.len());
        if payload_size > mss {
            eprintln!("Payload size > max segment size, handle backpressure");
        }
        // SND.NXT = next sequence number to be sent
        // 3.8 Data Communication
        // When the sender creates a segment and transmits it the sender advances SND.NXT.
        // ...
        // The amount by which the variables are advanced is the
        // length of the data and SYN or FIN flags in the segment.
        self.snd.nxt = self.snd.nxt.wrapping_add(payload_size as u32);
        if tcp_header.syn {
            _ = tcp_header.set_options(&[TcpOptionElement::MaximumSegmentSize(mss as u16)]);
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
        }
        if tcp_header.fin {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
        }

        // TODO - Avoid copy (directly write to the nic?)
        let mut buf = [0u8; MTU];
        // NOTE - Netcat does not ACK the SYN ACK message if the checksum is not set
        tcp_header.checksum = tcp_header
            .calc_checksum_ipv4(ip_header, &data[..payload_size])
            .expect("Cannot compute checksum");
        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip_header
                .set_payload_len(tcp_header.header_len().into())
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "IP payload too big"))?;
            ip_header
                .write(&mut unwritten)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Cannot write ip header"))?;
            tcp_header.write(&mut unwritten)?;
            unwritten.len()
        };
        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(())
    }

    /// 3.10.1 OPEN Call
    ///
    /// From a CLOSED STATE
    pub fn create(
        nic: &mut Iface,
        local: Socket,
        remote: Socket,
        urgent: bool,
        data: &[u8],
    ) -> Result<Self, Error> {
        let mut tcb = TransmissionControlBlock {
            local,
            remote,
            state: State::SynSent,
            snd: SendSequenceSpace::default(),
            rcv: RecvSequenceSpace::default(),
            initial_state: InitialState::Active,
            // TODO - Buffers will be passed to the send/recv methods
            buffer: BufWriter::new(File::create("tcp_data")?),
        };
        let mut tcp_header = tcb.get_tcp_header(tcb.snd.iss, tcb.snd.wnd);
        tcp_header.syn = true;
        tcp_header.urg = urgent;
        let mut ip_header = tcb.get_ip_header(tcp_header.header_len());
        tcb.write(nic, &mut tcp_header, &mut ip_header, data)?;

        Ok(tcb)
    }

    /// RFC9293 3.10.1. OPEN Call
    /// CLOSED STATE (i.e., TCB does not exist)
    ///
    /// Create a [TransmissionControlBlock](TransmissionControlBlock) in passive mode.
    pub fn listen(local: Socket, remote: Socket) -> Result<Self, io::Error> {
        Ok(Self {
            local,
            remote,
            state: State::Listen,
            snd: SendSequenceSpace::default(),
            rcv: RecvSequenceSpace::default(),
            initial_state: InitialState::Passive,
            // TODO - Buffers will be passed to the send/recv methods
            buffer: BufWriter::new(File::create("tcp_data")?),
        })
    }

    /// RFC9293 3.10.1 OPEN Call
    ///
    /// The [TransmissionControlBlock](TransmissionControlBlock) is in the LISTEN state (passive).
    /// This method is called when we want to go from passive (Listen) to active (SynSent).
    pub fn open(
        &mut self,
        nic: &mut Iface,
        local: Socket,
        remote: Socket,
        urgent: bool,
        data: &[u8],
    ) -> Result<(), Error> {
        if self.state != State::Listen {
            return Err(Error::ConnectionAlreadyExists);
        }
        self.local = local;
        self.remote = remote;
        self.state = State::SynSent;

        let mut tcp_header = self.get_tcp_header(self.snd.iss, self.snd.wnd);
        tcp_header.syn = true;
        tcp_header.urg = urgent;
        let mut ip_header = self.get_ip_header(tcp_header.header_len());
        self.write(nic, &mut tcp_header, &mut ip_header, data)?;

        Ok(())
    }

    /// RFC9293 3.10.7.4.  Other States
    /// +=========+=========+======================================+
    /// | Segment | Receive | Test                                 |
    /// | Length  | Window  |                                      |
    /// +=========+=========+======================================+
    /// | 0       | 0       | SEG.SEQ = RCV.NXT                    |
    /// +---------+---------+--------------------------------------+
    /// | 0       | >0      | RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND |
    /// +---------+---------+--------------------------------------+
    /// | >0      | 0       | not acceptable                       |
    /// +---------+---------+--------------------------------------+
    /// | >0      | >0      | RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND |
    /// |         |         |                                      |
    /// |         |         | or                                   |
    /// |         |         |                                      |
    /// |         |         | RCV.NXT =< SEG.SEQ+SEG.LEN-1 <       |
    /// |         |         | RCV.NXT+RCV.WND                      |
    /// +---------+---------+--------------------------------------+
    fn is_segment_acceptable(
        &self,
        seg_len: u32,
        rcv_wnd: u16,
        seg_seq: u32,
        rcv_nxt: u32,
        rcv_nxt_wnd: u32,
    ) -> bool {
        if seg_len == 0 {
            if rcv_wnd == 0 && seg_seq != rcv_nxt {
                eprintln!("Unacceptable segment: test case 1 failed");
                return false;
            }
            if rcv_wnd > 0 && !is_between_wrapped(rcv_nxt.wrapping_sub(1), seg_seq, rcv_nxt_wnd) {
                eprintln!("Unacceptable segment: test case 2 failed");
                return false;
            }
        } else if seg_len > 0 {
            if rcv_wnd == 0 {
                eprintln!("Unacceptable segment: test case 3");
                return false;
            }
            if rcv_wnd > 0
                && !(is_between_wrapped(rcv_nxt.wrapping_sub(1), seg_seq, rcv_nxt_wnd)
                    || is_between_wrapped(
                        rcv_nxt.wrapping_sub(1),
                        seg_seq.wrapping_add(seg_len).wrapping_sub(1),
                        rcv_nxt_wnd,
                    ))
            {
                eprintln!("Unacceptable segment: test case 4 failed");
                return false;
            }
        }

        true
    }

    // TODO - Reset Processing
    //      - Retransmissions
    pub fn on_segment<'segment>(
        &mut self,
        nic: &mut Iface,
        _ip_header: Ipv4HeaderSlice<'segment>,
        tcp_header: TcpHeaderSlice<'segment>,
        data: &'segment [u8],
    ) -> Result<(), Error> {
        // SEG.ACK = acknowledgment from the receiving TCP (next sequence number expected by the receiving TCP)
        // SEG.SEQ = first sequence number of a segment
        // SEG.LEN = the number of octets occupied by the data in the segment (counting SYN and FIN)
        let (seg_ack, seg_seq, mut seg_len) = (
            tcp_header.acknowledgment_number(),
            tcp_header.sequence_number(),
            data.len() as u32,
        );
        if tcp_header.syn() {
            seg_len += 1;
        }
        if tcp_header.fin() {
            seg_len += 1;
        }

        if self.state == State::Listen {
            // Documentation L.2->5
            if tcp_header.rst() {
                return Ok(());
            }
            // Documentation L.7->11
            if tcp_header.ack() {
                let mut response = self.get_tcp_header(seg_ack, self.snd.wnd);
                response.rst = true;
                let mut ip_header = self.get_ip_header(response.header_len());
                self.write(nic, &mut response, &mut ip_header, &[])?;
                return Ok(());
            }
            // Documentation L.13->17
            if tcp_header.syn() {
                // TODO - Check security
                let security_ok = true;
                if !security_ok {
                    let mut response = self.get_tcp_header(self.snd.iss, self.snd.wnd);
                    response.acknowledgment_number = seg_ack.wrapping_add(seg_len);
                    response.rst = true;
                    response.ack = true;
                    let mut ip_header = self.get_ip_header(response.header_len());
                    self.write(nic, &mut response, &mut ip_header, &[])?;
                    return Ok(());
                }
                // Documentation L.19->22
                self.rcv.nxt = seg_seq.wrapping_add(1);
                self.rcv.irs = seg_seq;

                let mut response = self.get_tcp_header(self.snd.iss, self.snd.wnd);
                response.acknowledgment_number = self.rcv.nxt;
                response.syn = true;
                response.ack = true;

                // Documentation L.24->30
                self.snd.nxt = self.snd.iss.wrapping_add(1);
                self.snd.una = self.snd.iss;
                self.state = State::SynReceived;
                let mut ip_header = self.get_ip_header(response.header_len());
                self.write(nic, &mut response, &mut ip_header, &[])?;

                // TODO - Process incoming control and data
                if !data.is_empty() {
                    eprintln!("Data processing not implemented");
                }
                return Ok(());
            }
            // Documentation L.32->37
        } else if self.state == State::SynSent {
            let (rst, seg_wnd) = (tcp_header.rst(), tcp_header.window_size());
            if tcp_header.ack() {
                // Documentation L.40->44
                if !is_between_wrapped(self.snd.iss.wrapping_add(1), seg_ack, self.snd.nxt) {
                    if rst {
                        return Ok(());
                    }
                    let mut response = self.get_tcp_header(seg_ack, self.snd.wnd);
                    response.rst = true;
                    let mut ip_header = self.get_ip_header(response.header_len());
                    self.write(nic, &mut response, &mut ip_header, &[])?;
                }
                // Documentation L.46->51
                if !is_between_wrapped(self.snd.una, seg_ack, self.snd.nxt.wrapping_add(1)) {
                    // Unacceptable ACK.
                    return Ok(());
                }
            }

            // Documentation L.53->61
            // TODO - Blind reset attack mitigation?

            // Documentation L.64->67
            if rst && seg_seq == self.rcv.nxt {
                if tcp_header.ack() {
                    return Err(Error::ConnectionReset);
                }
                return Ok(());
            }

            // TODO - Check the security
            // Documentation L.69->81

            // Fourth, check the SYN bit:
            // TODO - Assert this affirmation
            // This step should be reached only if the ACK is ok, or there is
            // no ACK, and the segment did not contain a RST.

            // Documentation L.83->86
            if tcp_header.syn() {
                self.rcv.nxt = seg_seq.wrapping_add(1);
                self.rcv.irs = seg_seq;
                if tcp_header.ack() {
                    self.snd.una = seg_ack;
                }
                // TODO - Any segments on the retransmission queue that are thereby acknowledged should be removed.

                // Documentation L88->90
                if self.snd.una > self.snd.iss {
                    self.state = State::Established;
                    let mut response = self.get_tcp_header(self.snd.iss, self.snd.wnd);
                    response.ack = true;
                    response.acknowledgment_number = self.rcv.nxt;
                    let mut ip_header = self.get_ip_header(response.header_len());
                    self.write(nic, &mut response, &mut ip_header, &[])?;
                // TODO - Documentation L.92->100
                } else {
                    // Documentation L.102->103
                    self.state = State::SynReceived;
                    let mut response = self.get_tcp_header(self.snd.iss, self.snd.wnd);
                    response.syn = true;
                    response.ack = true;
                    response.acknowledgment_number = self.rcv.nxt;
                    let mut ip_header = self.get_ip_header(response.header_len());
                    self.write(nic, &mut response, &mut ip_header, &[])?;
                    // Documentation L.105->108
                    self.snd.wnd = seg_wnd;
                    self.snd.wl1 = seg_seq;
                    self.snd.wl2 = seg_ack;
                    //  TODO - If there are other controls or text in the segment, queue them
                    //  for processing after the ESTABLISHED state has been reached,
                    //  return.
                    if !data.is_empty() {
                        println!("Queue segment data for processing");
                    }

                    // NOTE - Documentation L.110->117
                }
                return Ok(());
            }
        }
        if self.state == State::SynReceived || self.state.is_synchronized() {
            // Return immediately if the segment is unacceptable.
            if !self.is_segment_acceptable(
                seg_len,
                self.rcv.wnd,
                seg_seq,
                self.rcv.nxt,
                self.rcv.nxt.wrapping_add(self.rcv.wnd.into()),
            ) {
                // Documentation L.119->122
                if !tcp_header.rst() {
                    let mut response = self.get_tcp_header(self.snd.nxt, self.snd.wnd);
                    response.ack = true;
                    response.acknowledgment_number = self.rcv.nxt;
                    let mut ip_header = self.get_ip_header(response.header_len());
                    self.write(nic, &mut response, &mut ip_header, &[])?;
                }
                return Ok(());
            }

            // Documentation L.124->126

            if self.state == State::SynReceived {
                if tcp_header.rst() {
                    match self.initial_state {
                        InitialState::Passive => {
                            // Documentation L.128->131
                            self.state = State::Listen;
                            return Ok(());
                        }
                        InitialState::Active => {
                            // Documentation L.133->138
                            // TODO - Flush retransmission queue
                            return Err(Error::ConnectionRefused);
                        }
                    }
                }
                // TODO - Check the security
                // Documentation L.140->142

                // Documentation L.144->147
                if tcp_header.syn() && self.initial_state == InitialState::Passive {
                    self.state = State::Listen;
                    return Ok(());
                }
            } else {
                match self.state {
                    State::Established | State::FinWait1 | State::FinWait2 | State::CloseWait => {
                        if tcp_header.rst() {
                            // Documentation L.149->153
                            // TODO - Flush segments queues (same as retransmission queues?)
                            return Err(Error::ConnectionReset);
                        }
                    }
                    State::Closing | State::LastAck | State::TimeWait => {
                        if tcp_header.rst() {
                            return Err(Error::ConnectionReset);
                        }
                    }

                    // TODO - Check security
                    // Documentation L.155->165
                    _ => {
                        unimplemented!();
                    }
                }
                // NOTE - Documentation L.167->185

                // Documentation L.187->194
                if tcp_header.syn() {
                    // XXX - What sequence number to use?
                    let mut response = self.get_tcp_header(self.snd.nxt, self.snd.wnd);
                    response.rst = true;
                    let mut ip_header = self.get_ip_header(response.header_len());
                    self.write(nic, &mut response, &mut ip_header, &[])?;
                    return Err(Error::ConnectionReset);
                }
                // Documentation L.196->198
            }

            // Fifth, check the ACK bit
            // NOTE - Docunentation L.200->212
            if tcp_header.ack() {
                match self.state {
                    State::SynReceived => {
                        // Documentation L.214->219
                        if is_between_wrapped(self.snd.una, seg_ack, self.snd.nxt.wrapping_add(1)) {
                            self.state = State::Established;
                            self.snd.wnd = tcp_header.window_size();
                            self.snd.wl1 = seg_seq;
                            self.snd.wl2 = seg_ack;
                        } else {
                            // Documentation L.221->224
                            let mut response = self.get_tcp_header(seg_ack, self.snd.wnd);
                            response.rst = true;
                            let mut ip_header = self.get_ip_header(response.header_len());
                            self.write(nic, &mut response, &mut ip_header, &[])?;
                        }
                    }
                    State::Established
                    | State::FinWait1
                    | State::FinWait2
                    | State::CloseWait
                    | State::Closing => {
                        if is_between_wrapped(self.snd.una, seg_ack, self.snd.nxt.wrapping_add(1)) {
                            // If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <-
                            // SEG.ACK.  Any segments on the retransmission queue that
                            // are thereby entirely acknowledged are removed.  Users
                            // should receive positive acknowledgments for buffers that
                            // have been SENT and fully acknowledged (i.e., SEND buffer
                            // should be returned with "ok" response).
                            // If the ACK is a duplicate (SEG.ACK =< SND.UNA), it can be ignored.
                            if seg_ack <= self.snd.una {
                                return Ok(());
                            }
                            self.snd.una = seg_ack;
                            // If the ACK acks something not yet sent (SEG.ACK > SND.NXT),
                            // then send an ACK, drop the segment, and return.
                            if seg_ack > self.snd.nxt {
                                let mut response = self.get_tcp_header(seg_ack, self.snd.wnd);
                                response.ack = true;
                                // TODO - What should we acknowledge?
                                response.acknowledgment_number = self.rcv.nxt;
                                let mut ip_header = self.get_ip_header(response.header_len());
                                self.write(nic, &mut response, &mut ip_header, &[])?;
                                return Ok(());
                            }
                        } else if is_between_wrapped(
                            // If SND.UNA =< SEG.ACK =< SND.NXT, the send window should
                            // be updated.
                            self.snd.una.wrapping_sub(1),
                            seg_ack,
                            self.snd.nxt.wrapping_add(1),
                        ) {
                            // If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ
                            // and SND.WL2 =< SEG.ACK)), set:
                            // - SND.WND <- SEG.WND
                            // - SND.WL1 <- SEG.SEQ
                            // - SND.WL2 <- SEG.ACK
                            if self.snd.wl1 < seg_seq
                                || (self.snd.wl1 == seg_seq && self.snd.wl2 <= seg_ack)
                            {
                                self.snd.wnd = tcp_header.window_size();
                                self.snd.wl1 = seg_seq;
                                self.snd.wl2 = seg_ack;
                                // Note that SND.WND is an offset from SND.UNA, that SND.WL1
                                // records the sequence number of the last segment used to
                                // update SND.WND, and that SND.WL2 records the
                                // acknowledgment number of the last segment used to update
                                // SND.WND.  The check here prevents using old segments to
                                // update the window.
                            }
                        }
                        if self.state == State::FinWait1 {
                            // In addition to the processing for the ESTABLISHED state,
                            // if the FIN segment is now acknowledged, then enter FIN-
                            // WAIT-2 and continue processing in that state.
                            if tcp_header.fin() {
                                self.state = State::FinWait2;
                            }
                        } else if self.state == State::FinWait2 {
                            // In addition to the processing for the ESTABLISHED state,
                            // if the retransmission queue is empty, the user's CLOSE
                            // can be acknowledged ("ok") but do not delete the TCB.
                            // TODO - Check retransmission queue
                            println!("Check retransmission queue");
                        } else if self.state == State::Closing {
                            // In addition to the processing for the ESTABLISHED state,
                            // if the ACK acknowledges our FIN, then enter the TIME-WAIT
                            // state; otherwise, ignore the segment.
                            // TODO - How to know if "the ACK acknowledges our FIN"?
                            println!("Check if the ACK acknowledges our FIN");
                        } else if self.state == State::LastAck {
                            // The only thing that can arrive in this state is an
                            // acknowledgment of our FIN.  If our FIN is now
                            // acknowledged, delete the TCB, enter the CLOSED state, and
                            // return.
                            println!("Check if FIN is now acknowledged");
                        } else if self.state == State::TimeWait {
                            // The only thing that can arrive in this state is a
                            // retransmission of the remote FIN.  Acknowledge it, and
                            // restart the 2 MSL timeout.
                        }
                    }
                    state => {
                        unimplemented!("{state:?} processing not implemented");
                    }
                }
            } else {
                return Ok(());
            }
            // TODO - Sixth step, check urgent bit
            // -  ESTABLISHED STATE
            //
            // -  FIN-WAIT-1 STATE
            //
            // -  FIN-WAIT-2 STATE
            //
            //    o  If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and
            //       signal the user that the remote side has urgent data if the
            //       urgent pointer (RCV.UP) is in advance of the data consumed.
            //       If the user has already been signaled (or is still in the
            //       "urgent mode") for this continuous sequence of urgent data,
            //       do not signal the user again.
            //
            // -  CLOSE-WAIT STATE
            //
            // -  CLOSING STATE
            //
            // -  LAST-ACK STATE
            //
            // -  TIME-WAIT STATE
            //
            //    o  This should not occur since a FIN has been received from the
            //       remote side.  Ignore the URG.
            //
            //       -  ESTABLISHED STATE
            //       -  FIN-WAIT-1 STATE
            //       -  FIN-WAIT-2 STATE
            if self.state == State::Established
                || self.state == State::FinWait1
                || self.state == State::FinWait2
            {
                // TODO - Write to user recv buffer
                if !data.is_empty() {
                    self.buffer.write_all(data)?;
                    // Once in the ESTABLISHED state, it is possible to deliver
                    // segment data to user RECEIVE buffers.  Data from segments
                    // can be moved into buffers until either the buffer is full or
                    // the segment is empty.  If the segment empties and carries a
                    // PUSH flag, then the user is informed, when the buffer is
                    // returned, that a PUSH has been received.
                    //
                    // When the TCP endpoint takes responsibility for delivering
                    // the data to the user, it must also acknowledge the receipt
                    // of the data.
                    //
                    // Once the TCP endpoint takes responsibility for the data, it
                    // advances RCV.NXT over the data accepted, and adjusts RCV.WND
                    // as appropriate to the current buffer availability.  The
                    // total of RCV.NXT and RCV.WND should not be reduced.
                    // NOTE - SEG.SEQ+SEG.LEN-1 = last sequence number of a segment, so SEG.SEQ+SEG.LEN is the next byte we expect.
                    self.rcv.nxt = seg_seq.wrapping_add(seg_len);
                    // TODO - Take buffer availability into account
                    self.rcv.wnd = self.rcv.wnd.wrapping_sub(data.len() as u16);
                    // A TCP implementation MAY send an ACK segment acknowledging
                    // RCV.NXT when a valid segment arrives that is in the window
                    // but not at the left window edge (MAY-13).
                    //
                    // Please note the window management suggestions in
                    // Section 3.8.
                    //
                    // Send an acknowledgment of the form:
                    //
                    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                    let mut response = self.get_tcp_header(self.snd.nxt, self.snd.wnd);
                    response.ack = true;
                    response.acknowledgment_number = self.rcv.nxt;
                    let mut ip_header = self.get_ip_header(response.header_len());
                    self.write(nic, &mut response, &mut ip_header, &[])?;
                    // This acknowledgment should be piggybacked on a segment being
                    // transmitted if possible without incurring undue delay.
                }
            } else if self.state == State::CloseWait
                || self.state == State::Closing
                || self.state == State::LastAck
                || self.state == State::TimeWait
            {
                // This should not occur since a FIN has been received from the remote side.
                // Ignore the segment text.
                eprintln!("Code should not be reached since a FIN has been received from the remote side.");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_between_wrapped;

    #[test]
    fn wrapping_arithmetic() {
        let (start, x, end) = (2u32, 3u32, 4u32);
        assert!(is_between_wrapped(start, x, end));
        let (start, x, end) = (1, 2, u32::MAX);
        assert!(!is_between_wrapped(start, x, end));
    }
}
