### 3.10.7.2.  LISTEN STATE
First, check for a RST:
An incoming RST segment could not be valid since it could not
have been sent in response to anything sent by this incarnation
of the connection.  An incoming RST should be ignored.  Return.

Second, check for an ACK:
Any acknowledgment is bad if it arrives on a connection still
in the LISTEN state.  An acceptable reset segment should be
formed for any arriving ACK-bearing segment.  The RST should be
formatted as follows:
    <SEQ=SEG.ACK><CTL=RST>

Third, check for a SYN:
If the SYN bit is set, check the security.  If the security/
compartment on the incoming segment does not exactly match the
security/compartment in the TCB, then send a reset and return.
    <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and any other
control or text should be queued for processing later.  ISS
should be selected and a SYN segment sent of the form:
    <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
state should be changed to SYN-RECEIVED.  Note that any other
incoming control or data (combined with SYN) will be processed
in the SYN-RECEIVED state, but processing of SYN and ACK should
not be repeated.  If the listen was not fully specified (i.e.,
the remote socket was not fully specified), then the
unspecified fields should be filled in now.

Fourth, other data or control:
This should not be reached.  Drop the segment and return.  Any
other control or data-bearing segment (not containing SYN) must
have an ACK and thus would have been discarded by the ACK
processing in the second step, unless it was first discarded by
RST checking in the first step.

### 3.10.7.3.  SYN-SENT STATE
If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless
the RST bit is set, if so drop the segment and return)
   <SEQ=SEG.ACK><CTL=RST>
and discard the segment.  Return.

If SND.UNA < SEG.ACK =< SND.NXT, then the ACK is acceptable.
Some deployed TCP code has used the check SEG.ACK == SND.NXT
(using "==" rather than "=<"), but this is not appropriate
when the stack is capable of sending data on the SYN because
the TCP peer may not accept and acknowledge all of the data
on the SYN.

If the RST bit is set,
A potential blind reset attack is described in RFC 5961 [9].
The mitigation described in that document has specific
applicability explained therein, and is not a substitute for
cryptographic protection (e.g., IPsec or TCP-AO).  A TCP
implementation that supports the mitigation described in RFC
5961 SHOULD first check that the sequence number exactly
matches RCV.NXT prior to executing the action in the next
paragraph.


If the ACK was acceptable, then signal to the user "error:
connection reset", drop the segment, enter CLOSED state,
delete TCB, and return.  Otherwise (no ACK), drop the
segment and return.

If the security/compartment in the segment does not exactly
match the security/compartment in the TCB, send a reset:
If there is an ACK,
<SEQ=SEG.ACK><CTL=RST>
Otherwise,
<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
If a reset was sent, discard the segment and return.

If the SYN bit is on and the security/compartment is
acceptable, then RCV.NXT is set to SEG.SEQ+1, IRS is set to
SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
is an ACK), and any segments on the retransmission queue that
are thereby acknowledged should be removed.

If the SYN bit is on and the security/compartment is
acceptable, then RCV.NXT is set to SEG.SEQ+1, IRS is set to
SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
is an ACK).

If SND.UNA > ISS (our SYN has been ACKed), change the
connection state to ESTABLISHED, form an ACK segment
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

Data or controls that were queued for
transmission MAY be included.  Some TCP implementations
suppress sending this segment when the received segment
contains data that will anyways generate an acknowledgment in
the later processing steps, saving this extra acknowledgment of
the SYN from being sent.  If there are other controls or text
in the segment, then continue processing at the sixth step
under Section 3.10.7.4 where the URG bit is checked; otherwise,
return.

Otherwise, enter SYN-RECEIVED, form a SYN,ACK segment
<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

Set the variables:
SND.WND <- SEG.WND
SND.WL1 <- SEG.SEQ
SND.WL2 <- SEG.ACK

It is legal to send and receive application data on
SYN segments (this is the "text in the segment" mentioned
above).  There has been significant misinformation and
misunderstanding of this topic historically.  Some firewalls
and security devices consider this suspicious.  However, the
capability was used in T/TCP [21] and is used in TCP Fast Open
(TFO) [48], so is important for implementations and network
devices to permit.

If an incoming segment is not acceptable, an acknowledgment
should be sent in reply (unless the RST bit is set, if so
drop the segment and return):
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

RFC9293 mentions a blind reset attack mitigation approach and 3 checks to do
if the mitigation is implemented. We ignore it for now as the mitigation is not
implemented.

If this connection was initiated with a passive OPEN
(i.e., came from the LISTEN state), then return this
connection to LISTEN state and return.  The user need not
be informed.

If this connection was initiated with an
active OPEN (i.e., came from SYN-SENT state), then the
connection was refused; signal the user "connection
refused".  In either case, the retransmission queue
should be flushed.  And in the active OPEN case, enter
the CLOSED state and delete the TCB, and return.

If the security/compartment in the segment does not exactly
match the security/compartment in the TCB, then send a reset
and return.

Fourth, check the SYN bit:
 SYN-RECEIVED STATE
 If the connection was initiated with a passive OPEN, then
 return this connection to the LISTEN state and return.

If the RST bit is set, then any outstanding RECEIVEs and
SEND should receive "reset" responses.  All segment queues
should be flushed.  Users should also receive an unsolicited
general "connection reset" signal.  Enter the CLOSED state,
delete the TCB, and return.

If the security/compartment in the segment does not exactly
match the security/compartment in the TCB, then send a
reset; any outstanding RECEIVEs and SEND should receive
"reset" responses.  All segment queues should be flushed.
Users should also receive an unsolicited general "connection
reset" signal.  Enter the CLOSED state, delete the TCB, and
return.
Note this check is placed following the sequence check to
prevent a segment from an old connection between these port
numbers with a different security from causing an abort of the
current connection.

We do not follow RFC5961 so the following paragraph does not apply.
If the SYN bit is set in these synchronized states, it may
be either a legitimate new connection attempt (e.g., in the
case of TIME-WAIT), an error where the connection should be
reset, or the result of an attack attempt, as described in
RFC 5961 [9].  For the TIME-WAIT state, new connections can
be accepted if the Timestamp Option is used and meets
expectations (per [40]).  For all other cases, RFC 5961
provides a mitigation with applicability to some situations,
though there are also alternatives that offer cryptographic
protection (see Section 7).  RFC 5961 recommends that in
these synchronized states, if the SYN bit is set,
irrespective of the sequence number, TCP endpoints MUST send
a "challenge ACK" to the remote peer:
<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
After sending the acknowledgment, TCP implementations MUST
drop the unacceptable segment and stop processing further.
Note that RFC 5961 and Errata ID 4772 [99] contain
additional ACK throttling notes for an implementation.

For implementations that do not follow RFC 5961, the
original behavior described in RFC 793 follows in this
paragraph.  If the SYN is in the window it is an error: send
a reset, any outstanding RECEIVEs and SEND should receive
"reset" responses, all segment queues should be flushed, the
user should also receive an unsolicited general "connection
reset" signal, enter the CLOSED state, delete the TCB, and
return.

If the SYN is not in the window, this step would not be
reached and an ACK would have been sent in the first step
(sequence number check).

RFC 5961 [9], Section 5 describes a potential blind data
injection attack, and mitigation that implementations MAY
choose to include (MAY-12).  TCP stacks that implement RFC
5961 MUST add an input check that the ACK value is
acceptable only if it is in the range of ((SND.UNA -
MAX.SND.WND) =< SEG.ACK =< SND.NXT).  All incoming segments
whose ACK value doesn't satisfy the above condition MUST be
discarded and an ACK sent back.  The new state variable
MAX.SND.WND is defined as the largest window that the local
sender has ever received from its peer (subject to window
scaling) or may be hard-coded to a maximum permissible
window value.  When the ACK value is acceptable, the per-
state processing below applies:


