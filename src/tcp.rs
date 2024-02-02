// NOTE - When the tcp segment is not properly routed (wrong destination port), the remote instance sends a RST with SEQ == ACK
//        3 0.475377651  192.168.0.1 → 192.168.0.2  TCP 64 35688 → 5355 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2418554181 TSecr=0 WS=128 TFO=R
//        4 0.475390621  192.168.0.2 → 192.168.0.1  TCP 40 35688 → 5355 [SYN, ACK] Seq=0 Ack=1 Win=10 Len=0
//        5 0.475399731  192.168.0.1 → 192.168.0.2  TCP 40 5355 → 35688 [RST] Seq=1 Win=0 Len=0
//
//      - Check "Initial sequence number selecton" paragraph from RFC9293.

use {
    super::{error::Error, Socket, MTU},
    etherparse::{IpTrafficClass, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice},
    std::io,
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

///     Kind     Length    Meaning
///     ----     ------    -------
///      0         -       End of option list.
///      1         -       No-Operation.
///      2         4       Maximum Segment Size.
///
#[derive(Debug)]
enum Options {
    /// End of option list.
    EndOfOptionList,
    /// No-Operation
    NoOp,
    /// Maximum Segment size
    MaxSegmentSize,
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

#[derive(Debug)]
enum UserCall {
    Open,
    Send,
    Receive,
    Close,
    Abort,
    Status,
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
struct SendSequenceSpace {
    /// Send unacknowledged
    una: u32,
    /// Send next
    nxt: u32,
    /// Send window
    wnd: u16,
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
            wnd: 10,
            up: false,
            wl1: 0,
            wl2: 0,
        }
    }
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
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
struct RecvSequenceSpace {
    /// Receive next
    nxt: u32,
    /// Receive window
    wnd: u16,
    /// Receive urgent pointer
    up: bool,
    /// Initial receive sequence number
    irs: u32,
}

impl Default for RecvSequenceSpace {
    fn default() -> Self {
        Self {
            nxt: 0,
            wnd: 10,
            up: false,
            irs: 0,
        }
    }
}

/// NOTE - In other words, you can shift things so that start = 0.
/// The equation becomes a simple matter of comparison (x < end) with a small bit of fudging depending on which bounds you want to include (0 < x <= end, I think).
// TODO - Test with some values
fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

#[derive(Debug)]
pub struct TransmissionControlBlock {
    /// Address and port of this instance
    local: Socket,
    /// Address and port of the remote instance
    remote: Socket,
    state: State,
    snd: SendSequenceSpace,
    rcv: RecvSequenceSpace,
}

impl TransmissionControlBlock {
    pub fn state(&self) -> State {
        self.state
    }

    fn write(
        &mut self,
        nic: &mut Iface,
        tcp_header: &mut TcpHeader,
        ip_header: &mut Ipv4Header,
        data: &[u8],
    ) -> io::Result<()> {
        // TODO - data can be > buf, handle backpressure/send queue.
        let payload_size = std::cmp::min(MTU, data.len());
        if payload_size > MTU {
            eprintln!("Payload size > MTU, handle backpressure");
        }
        // SND.NXT = next sequence number to be sent
        // 3.8 Data Communication
        // When the sender creates a segment and transmits it the sender advances SND.NXT.
        // ...
        // The amount by which the variables are advanced is the
        // length of the data and SYN or FIN flags in the segment.
        self.snd.nxt = self.snd.nxt.wrapping_add(payload_size as u32);
        if tcp_header.syn {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
        }
        if tcp_header.fin {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
        }

        // TODO - Avoid copy (directly write to the nic?)
        let mut buf = [0u8; MTU];
        // NOTE - Netcat does not ACK the SYN ACK message if the checksum is not set
        tcp_header.checksum = tcp_header
            .calc_checksum_ipv4(&ip_header, &data[..payload_size])
            .expect("Cannot compute checksum");
        let unwritten = {
            let mut unwritten = &mut buf[..];
            // TODO - Handle error
            ip_header
                .set_payload_len(tcp_header.header_len().into())
                .expect("IP payload len too big");
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
    /// CLOSED STATE
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
            state: State::Listen,
            snd: SendSequenceSpace::default(),
            rcv: RecvSequenceSpace::default(),
        };
        let mut tcp_header = TcpHeader::new(remote.port, local.port, tcb.snd.iss, tcb.snd.wnd);
        tcp_header.syn = true;
        tcp_header.urg = urgent;

        tcb.local = local;
        tcb.remote = remote;
        tcb.state = State::SynSent;
        let mut ip_header = Ipv4Header::new(
            tcp_header.header_len(),
            TTL,
            IpTrafficClass::Tcp,
            local.address.octets(),
            remote.address.octets(),
        );
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
        })
    }

    /// RFC9293 3.10.1 OPEN Call
    ///
    /// The [TransmissionControlBlock](TransmissionControlBlock) is in the LISTEN state.
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
        let mut tcp_header = TcpHeader::new(remote.port, local.port, self.snd.iss, self.snd.wnd);
        tcp_header.syn = true;
        tcp_header.urg = urgent;

        self.local = local;
        self.remote = remote;
        self.state = State::SynSent;

        let mut ip_header = Ipv4Header::new(
            tcp_header.header_len(),
            TTL,
            IpTrafficClass::Tcp,
            local.address.octets(),
            remote.address.octets(),
        );
        self.write(nic, &mut tcp_header, &mut ip_header, data)?;

        Ok(())
    }

    fn send_rst<'segment>(
        &mut self,
        nic: &mut Iface,
        tcp_header: TcpHeaderSlice<'segment>,
        ip_header: Ipv4HeaderSlice<'segment>,
        data: &[u8],
    ) -> io::Result<()> {
        eprintln!("RST implementation incomplete");
        let mut rst = TcpHeader::new(self.local.port, self.remote.port, 0, 0);
        // 2.  If the connection is in any non-synchronized state (LISTEN,
        // SYN-SENT, SYN-RECEIVED), and the incoming segment acknowledges
        // something not yet sent (the segment carries an unacceptable ACK), or
        // if an incoming segment has a security level or compartment which
        // does not exactly match the level and compartment requested for the
        // connection, a reset is sent.
        // ...
        // ( NOTE - Original text truncated, discussion about precedence level that might not be important for now)
        // ...
        if !self.state.is_synchronized() {
            rst.rst = true;
            // If the incoming segment has an ACK field, the reset takes its
            // sequence number from the ACK field of the segment, otherwise the
            // reset has sequence number zero and the ACK field is set to the sum
            // of the sequence number and segment length of the incoming segment.
            // The connection remains in the same state.
            if tcp_header.ack() {
                rst.sequence_number = tcp_header.acknowledgment_number();
            } else {
                rst.ack = true;
                rst.acknowledgment_number = tcp_header.sequence_number() + data.len() as u32;
            }
            let mut ip_header = Ipv4Header::new(
                rst.header_len(),
                TTL,
                IpTrafficClass::Tcp,
                self.local.address.octets(),
                self.remote.address.octets(),
            );
            self.write(nic, &mut rst, &mut ip_header, &[])?;
        }
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.

        // If an incoming segment has a security level, or compartment, or
        // precedence which does not exactly match the level, and compartment,
        // and precedence requested for the connection,a reset is sent and
        // connection goes to the CLOSED state.  The reset takes its sequence
        // number from the ACK field of the incoming segment.
        else {
            // TODO
            eprintln!("RST in synchronized state not implemented");
        }

        // TODO
        // nic.send();
        eprintln!("Send RST segment to nic");

        Ok(())
    }

    // There are essentially three cases:
    //   1) The user initiates by telling the TCP to CLOSE the connection
    //   2) The remote TCP initiates by sending a FIN control signal
    //   3) Both users CLOSE simultaneously
    fn close<'segment>(
        &mut self,
        nic: &mut Iface,
        tcp_header: TcpHeaderSlice<'segment>,
        ip_header: Ipv4HeaderSlice<'segment>,
    ) {
        let mut fin = TcpHeader::new(self.local.port, self.remote.port, 0, 0);
        fin.fin = true;
        // Case 1:  Local user initiates the close

        //   In this case, a FIN segment can be constructed and placed on the
        //   outgoing segment queue.  No further SENDs from the user will be
        //   accepted by the TCP, and it enters the FIN-WAIT-1 state.  RECEIVEs
        //   are allowed in this state.  All segments preceding and including FIN
        //   will be retransmitted until acknowledged.  When the other TCP has
        //   both acknowledged the FIN and sent a FIN of its own, the first TCP
        //   can ACK this FIN.  Note that a TCP receiving a FIN will ACK but not
        //   send its own FIN until its user has CLOSED the connection also.
        self.state = State::FinWait1;

        unimplemented!("Close not implemented");
    }

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
            } else if rcv_wnd > 0
                && !is_between_wrapped(rcv_nxt.wrapping_sub(1), seg_seq, rcv_nxt_wnd)
            {
                eprintln!("Unacceptable segment: test case 2 failed");
                return false;
            }
        } else if seg_len > 0 {
            if rcv_wnd == 0 {
                eprintln!("Unacceptable segment: test case 3");
                return false;
            } else if rcv_wnd > 0
                && !(is_between_wrapped(rcv_nxt.wrapping_sub(1), seg_seq, rcv_nxt_wnd)
                    || is_between_wrapped(
                        rcv_nxt.wrapping_sub(1),
                        seg_seq.wrapping_add(seg_len).wrapping_sub(1),
                        rcv_nxt_wnd,
                    ))
            {
                eprintln!("Unacceptable segment: test case 2 failed");
                return false;
            }
        }

        true
    }

    // TODO - Check RFC9293 3.10. Event processing
    //      - Reset Processing
    //      - Retransmissions
    //      - Return approriate errors instead ok Ok()'s
    pub fn on_segment<'segment>(
        &mut self,
        nic: &mut Iface,
        ip_header: Ipv4HeaderSlice<'segment>,
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

        match self.state {
            // 3.10.7.2.  LISTEN STATE
            State::Listen => {
                // First, check for a RST:
                // An incoming RST segment could not be valid since it could not
                // have been sent in response to anything sent by this incarnation
                // of the connection.  An incoming RST should be ignored.  Return.
                if tcp_header.rst() {
                    return Ok(());
                }

                // Second, check for an ACK:
                // Any acknowledgment is bad if it arrives on a connection still
                // in the LISTEN state.  An acceptable reset segment should be
                // formed for any arriving ACK-bearing segment.  The RST should be
                // formatted as follows: <SEQ=SEG.ACK><CTL=RST>
                if tcp_header.ack() {
                    let mut response =
                        TcpHeader::new(self.local.port, self.remote.port, seg_ack, 0);
                    response.rst = true;
                    let mut ip_header = Ipv4Header::new(
                        response.header_len(),
                        TTL,
                        IpTrafficClass::Tcp,
                        self.local.address.octets(),
                        self.remote.address.octets(),
                    );
                    self.write(nic, &mut response, &mut ip_header, &[])?;

                    return Ok(());
                }

                // Third, check for a SYN:
                // -  If the SYN bit is set, check the security.  If the security/
                //    compartment on the incoming segment does not exactly match the
                //    security/compartment in the TCB, then send a reset and return.
                //    <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                if tcp_header.syn() {
                    // TODO - Check security
                    if false {
                        let mut response =
                            TcpHeader::new(self.local.port, self.remote.port, self.snd.iss, 0);
                        response.acknowledgment_number =
                            tcp_header.sequence_number().wrapping_add(seg_len);
                        response.rst = true;
                        response.ack = true;

                        let mut ip_header = Ipv4Header::new(
                            response.header_len(),
                            TTL,
                            IpTrafficClass::Tcp,
                            self.local.address.octets(),
                            self.remote.address.octets(),
                        );
                        self.write(nic, &mut response, &mut ip_header, &[])?;
                        return Ok(());
                    }

                    // -  Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other
                    //    control or text should be queued for processing later.  ISS
                    //    should be selected and a SYN segment sent of the form:
                    //       <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                    self.rcv.nxt = seg_seq.wrapping_add(1);
                    self.rcv.irs = seg_seq;

                    let mut response =
                        TcpHeader::new(self.local.port, self.remote.port, self.snd.iss, 0);
                    response.acknowledgment_number = self.rcv.nxt;
                    response.syn = true;
                    response.ack = true;

                    // -  SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
                    //    state should be changed to SYN-RECEIVED.  Note that any other
                    //    incoming control or data (combined with SYN) will be processed
                    //    in the SYN-RECEIVED state, but processing of SYN and ACK should
                    //    not be repeated.  If the listen was not fully specified (i.e.,
                    //    the remote socket was not fully specified), then the
                    //    unspecified fields should be filled in now.
                    self.snd.nxt = self.snd.iss.wrapping_add(1);
                    self.snd.una = self.snd.iss;
                    self.state = State::SynReceived;
                    let mut ip_header = Ipv4Header::new(
                        response.header_len(),
                        TTL,
                        IpTrafficClass::Tcp,
                        self.local.address.octets(),
                        self.remote.address.octets(),
                    );
                    self.write(nic, &mut response, &mut ip_header, &[])?;

                    // TODO - Process incoming control and data
                    if !data.is_empty() {
                        eprintln!("Data processing not implemented");
                    }
                    return Ok(());
                }

                // Fourth, other data or control:
                // -  This should not be reached.  Drop the segment and return.  Any
                //    other control or data-bearing segment (not containing SYN) must
                //    have an ACK and thus would have been discarded by the ACK
                //    processing in the second step, unless it was first discarded by
                //    RST checking in the first step.
            }
            // 3.10.7.3.  SYN-SENT STATE
            State::SynSent => {
                let (rst, seg_wnd) = (tcp_header.rst(), tcp_header.window_size());
                if tcp_header.ack() {
                    // If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless
                    // the RST bit is set, if so drop the segment and return)
                    //    <SEQ=SEG.ACK><CTL=RST>
                    // and discard the segment.  Return.
                    if !is_between_wrapped(self.snd.iss.wrapping_add(1), seg_ack, self.snd.nxt) {
                        if rst {
                            return Ok(());
                        }
                        let mut response =
                            TcpHeader::new(self.local.port, self.remote.port, seg_ack, 0);
                        response.rst = true;
                        let mut ip_header = Ipv4Header::new(
                            response.header_len(),
                            TTL,
                            IpTrafficClass::Tcp,
                            self.local.address.octets(),
                            self.remote.address.octets(),
                        );
                        self.write(nic, &mut response, &mut ip_header, &[])?;
                    }

                    // If SND.UNA < SEG.ACK =< SND.NXT, then the ACK is acceptable.
                    // Some deployed TCP code has used the check SEG.ACK == SND.NXT
                    // (using "==" rather than "=<"), but this is not appropriate
                    // when the stack is capable of sending data on the SYN because
                    // the TCP peer may not accept and acknowledge all of the data
                    // on the SYN.
                    let snd_una = self.snd.una;
                    if !is_between_wrapped(snd_una, seg_ack, self.snd.nxt.wrapping_add(1)) {
                        // Unacceptable ACK.
                        return Ok(());
                    }
                }

                // TODO - Blind reset attack mitigation?
                // If the RST bit is set,
                //  A potential blind reset attack is described in RFC 5961 [9].
                //  The mitigation described in that document has specific
                //  applicability explained therein, and is not a substitute for
                //  cryptographic protection (e.g., IPsec or TCP-AO).  A TCP
                //  implementation that supports the mitigation described in RFC
                //  5961 SHOULD first check that the sequence number exactly
                //  matches RCV.NXT prior to executing the action in the next
                //  paragraph.

                //  If the ACK was acceptable, then signal to the user "error:
                //  connection reset", drop the segment, enter CLOSED state,
                //  delete TCB, and return.  Otherwise (no ACK), drop the
                //  segment and return.
                if rst && seg_seq == self.rcv.nxt {
                    if tcp_header.ack() {
                        return Err(Error::ConnectionReset);
                    }
                    return Ok(());
                }

                // TODO - Check the security
                // If the security/compartment in the segment does not exactly
                // match the security/compartment in the TCB, send a reset:
                // If there is an ACK,
                // <SEQ=SEG.ACK><CTL=RST>
                // Otherwise,
                // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                // If a reset was sent, discard the segment and return.

                // If the SYN bit is on and the security/compartment is
                // acceptable, then RCV.NXT is set to SEG.SEQ+1, IRS is set to
                // SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
                // is an ACK), and any segments on the retransmission queue that
                // are thereby acknowledged should be removed.

                // Fourth, check the SYN bit:
                // TODO - Assert this affirmation
                // This step should be reached only if the ACK is ok, or there is
                // no ACK, and the segment did not contain a RST.

                // If the SYN bit is on and the security/compartment is
                // acceptable, then RCV.NXT is set to SEG.SEQ+1, IRS is set to
                // SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
                // is an ACK).
                if tcp_header.syn() {
                    self.rcv.nxt = seg_seq.wrapping_add(1);
                    self.rcv.irs = seg_seq;
                    if tcp_header.ack() {
                        self.snd.una = seg_ack;
                    }
                    // TODO - Any segments on the retransmission queue that are thereby acknowledged should be removed.

                    // If SND.UNA > ISS (our SYN has been ACKed), change the
                    // connection state to ESTABLISHED, form an ACK segment
                    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                    if self.snd.una > self.snd.iss {
                        self.state = State::Established;
                        let mut response =
                            TcpHeader::new(self.local.port, self.remote.port, self.snd.iss, 0);
                        response.ack = true;
                        response.acknowledgment_number = self.rcv.nxt;
                        let mut ip_header = Ipv4Header::new(
                            response.header_len(),
                            TTL,
                            IpTrafficClass::Tcp,
                            self.local.address.octets(),
                            self.remote.address.octets(),
                        );
                        self.write(nic, &mut response, &mut ip_header, &[])?;
                    // TODO - Data or controls that were queued for
                    // transmission MAY be included.  Some TCP implementations
                    // suppress sending this segment when the received segment
                    // contains data that will anyways generate an acknowledgment in
                    // the later processing steps, saving this extra acknowledgment of
                    // the SYN from being sent.  If there are other controls or text
                    // in the segment, then continue processing at the sixth step
                    // under Section 3.10.7.4 where the URG bit is checked; otherwise,
                    // return.
                    } else {
                        // Otherwise, enter SYN-RECEIVED, form a SYN,ACK segment
                        // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                        self.state = State::SynReceived;
                        let mut response =
                            TcpHeader::new(self.local.port, self.remote.port, self.snd.iss, 0);
                        response.syn = true;
                        response.ack = true;
                        response.acknowledgment_number = self.rcv.nxt;
                        let mut ip_header = Ipv4Header::new(
                            response.header_len(),
                            TTL,
                            IpTrafficClass::Tcp,
                            self.local.address.octets(),
                            self.remote.address.octets(),
                        );
                        self.write(nic, &mut response, &mut ip_header, &[])?;
                        // Set the variables:
                        //     SND.WND <- SEG.WND
                        //     SND.WL1 <- SEG.SEQ
                        //     SND.WL2 <- SEG.ACK
                        self.snd.wnd = seg_wnd;
                        self.snd.wl1 = seg_seq;
                        self.snd.wl2 = seg_ack;
                        //  TODO - If there are other controls or text in the segment, queue them
                        //  for processing after the ESTABLISHED state has been reached,
                        //  return.

                        // NOTE - It is legal to send and receive application data on
                        // SYN segments (this is the "text in the segment" mentioned
                        // above).  There has been significant misinformation and
                        // misunderstanding of this topic historically.  Some firewalls
                        // and security devices consider this suspicious.  However, the
                        // capability was used in T/TCP [21] and is used in TCP Fast Open
                        // (TFO) [48], so is important for implementations and network
                        // devices to permit.
                    }

                    return Ok(());
                }
            }
            State::SynReceived
            | State::Established
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing
            | State::LastAck
            | State::TimeWait => {
                if !self.is_segment_acceptable(
                    seg_len,
                    self.rcv.wnd,
                    seg_seq,
                    self.rcv.nxt,
                    self.rcv.nxt.wrapping_add(self.rcv.wnd.into()),
                ) {
                    // TODO
                }
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
