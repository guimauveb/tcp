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
