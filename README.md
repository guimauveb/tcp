# Transmission Control Protocol

Rust implementation of the Transmission Control Protocol following [RFC 9293](https://datatracker.ietf.org/doc/rfc9293/).

## Notes

This is for learning puproses only.

The current state of the implementation correctly handles incoming data segments from a remote instance (assuming segments arrive in the order they were sent).
There is still a lot of work to do to ensure the protocol is correctly implemented.

## TODO
- Test sending data to a remote instance
- Handle closing handshake
- Handle duplicate and out of order segments
- Clean code

