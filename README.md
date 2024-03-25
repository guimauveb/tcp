# Transmission Control Protocol

Rust implementation of the Transmission Control Protocol following [RFC 9293](https://datatracker.ietf.org/doc/rfc9293/).

## Notes

This is for learning puproses only.

The current state of the implementation correctly handles and writes incoming data segments from a remote instance.

## Usage

Running `./run.sh` creates a socket listening on `192.168.0.2:5335`.

## TODO
- Test sending data to a remote instance
- Handle closing handshake
- Test duplicate and out of order segments
- Refactoring

