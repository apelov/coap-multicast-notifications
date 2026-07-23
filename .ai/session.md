# Session

## Goal
Implement a fully documented, runnable, and maintainable C implementation of the CoAP Multicast Observe mechanism based on `draft-ietf-core-observe-multicast-notifications` and interoperable with the Java reference implementation.

## Status
Completed.

## Done
- CBOR helper using `libcbor` that handles IP-to-bytes and default-port-omission, matching Java's exact binary format.
- OSCORE configuration helper using `libcoap` that supports symmetric client/server settings.
- CoAP Multicast Observe server (`src/server.c`) that intercepts unicast GET observe registrations, responds with `5.03` containing the CBOR `tp_info`, and broadcasts NON multicast notifications.
- CoAP Multicast Observe client (`src/client.c`) that registers, parses `tp_info`, joins the multicast group, and receives notifications.
- Warning-free compilation setup via `Makefile` linking `libcoap` and `libcbor`.
- Clean, readable `README.md` with instructions and Wireshark details.
- Added orchestrator script `run_demo.sh` to compile, launch a server, and run a configurable number of clients in parallel.



