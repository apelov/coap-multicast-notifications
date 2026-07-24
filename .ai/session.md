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
- Added interoperability orchestrator script `interop_demo.sh` to manage mixed Java and C clients/servers.
- Fixed `coap_address_t` size structure initialization in C codebase (resolving socket bind/connect failures on macOS).
- Enabled line-buffered output on C client/server `stdout` to ensure instant redirection logging.
- Added packet capturing demo script `run_pcap_demo.sh` that captures the exchange in `demo.pcap` and prints a summary.
- Added `run_java_server_pcap.sh` and `run_c_server_pcap.sh` to automate capturing and merging pcaps for both C and Java servers with mixed clients.
- Refactored C client (`src/client.c`) to eliminate the unsolicited multicast GET request/phantom transmission over the wire, making it completely passive on the multicast group and verifying tokens in `hnd_response`.
- Implemented `ph_req` and `last_notif` CBOR optional field encoding inside the C server's informative response (`src/server.c` / `src/cbor_helper.c`), providing fully compliant payload structure parsed successfully by the Java reference client.
- Added cross-platform support (macOS/Linux preprocessors for lo/lo0, Makefile OS detection) and packaged clean source codes, runnable scripts, and PCAP interop evidence into `coap_multicast_observe_package.zip`.









