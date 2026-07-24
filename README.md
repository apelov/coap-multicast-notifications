# CoAP Multicast Observe: Interoperable C Implementation

> [!NOTE]
> This codebase was developed with Gemini, during a session with Alexander Pelov, Marco Tiloca, and Rikard Hoglund.
> This is a first version, which provides a first level of interoperability without security.

This repository contains a fully documented, runnable, and maintainable C implementation of the CoAP Multicast Observe mechanism based on the IETF draft `draft-ietf-core-observe-multicast-notifications`.

It is designed to interoperate with the Java reference implementation from the `adriankastrati/californium-thesis-work` repository (`multicast-notifications` branch) by matching its CBOR encoding, CoAP option formats, and protocol state machine.

---

## Technical Features

1. **Passive Multicast Client**: The C client (`coap_client`) performs a silent multicast join. It sends no unsolicited multicast request on the wire, listening purely passively and validating group tokens dynamically.
2. **CBOR Informative Response (RFC compliance)**: The C server (`coap_server`) responds to observe requests with a `5.03 Service Unavailable` containing a complete CBOR payload containing:
   - **Key 0 (`tp_info`)**: The transport info mapping `[scheme-id, authority]` for server/client endpoints and the group token.
   - **Key 1 (`ph_req`)**: The client's unicast GET request represented in full UDP wire format (incorporating CoAP header `0x40 0x01...`), matching the decoding expectations of Californium.
   - **Key 2 (`last_notif`)**: The initial multicast notification represented in transport-independent CoAP format (`[Code] [Options...] [0xFF Payload]`).
3. **Cross-Platform**: Compiles and runs out of the box on both **macOS** and **Ubuntu/Linux**.

---

## Prerequisites & Installation

### Ubuntu/Linux
Install the compiler toolchain, packet utilities, and development headers for `libcoap` and `libcbor`:
```bash
sudo apt-get update
sudo apt-get install -y build-essential clang pkg-config libcoap3-dev libcbor-dev tshark wireshark
```

### macOS
Install the libraries via Homebrew:
```bash
brew install libcoap libcbor pkg-config
```

---

## Compilation

Build the client, server, and macOS socket-hooking shim using the provided cross-platform `Makefile`:
```bash
make
```
This generates the `coap_server` and `coap_client` binaries.

---

## Runnable Scripts (Ubuntu & macOS Portable)

### 1. Conflict-Free Interop Run (1 Client)
To run a clean interop test between the C Client and the Java Server, run:
```bash
./run_java_server_1c.sh
```
This script will:
- Spin up the Java Server.
- Run 1 C Client bound to the wildcard address `0.0.0.0:56830`.
- Capture all traffic for 60 seconds.
- Output a clean trace file `java_server_1c.pcap` showing the complete registration handshake and multicast notifications.

### 2. Multi-Process Interop Run (3 Clients)
To run 3 C Clients concurrently against the Java Server:
```bash
./run_java_server_3c.sh
```
- **Ubuntu/Linux**: Loops back the entire `127.0.0.0/8` subnet natively. Sockets successfully bind to `127.0.0.1`, `127.0.0.2`, and `127.0.0.3` without port conflicts.
- **macOS**: Requires registering the loopback IP aliases first (`sudo ifconfig lo0 alias 127.0.0.2 && sudo ifconfig lo0 alias 127.0.0.3`).
- **Multicast Routing**: The C clients automatically detect loopback binding and join the multicast group on the loopback interface (`lo` on Linux, `lo0` on macOS).

### 3. C Server Interop Run (Mixed Clients)
To test the C Server (`coap_server`) with **1 C Client** and **1 Java Client** concurrently, run:
```bash
./run_c_server_interop.sh
```
- This runs the C Server.
- Registers 1 C Client (bound to `127.0.0.2`) and 1 Java Client (via `AClient`) to it.
- Generates `c_server_interop.pcap` showing both unicast handshakes (using Content-Format `12`) and subsequent multicast notifications.

---

## Java Client Patch File

During interop testing, we identified a bug in the Java Client's multicast observe setup (`MulticastObserveClient.java`):
- The draft specifies that `ph_req` is serialized in a transport-independent CoAP format (starting directly with the Code byte, e.g. `0x01` for `GET`).
- The Java client erroneously parsed this using `UdpDataParser.parseMessage()`, which expects a standard 4-byte UDP CoAP header and crashes with `MessageFormatException: UDP Message has invalid version: 0` if the header is missing.
- We also resolved an issue where `NetworkInterfacesUtil` returned `null` for public IPv4 addresses.

We have included a git patch file **`java_client_ph_req_parser.patch`** in the package root. You can apply it directly to your Californium workspace to make the Java client fully draft-compliant:
```bash
cd /path/to/californium-thesis-work
git apply /path/to/java_client_ph_req_parser.patch
```

---

## PCAP Evidences

- **`java_server_1c.pcap`**: Unicast registration and multicast notification flow between Java Server and 1 C Client.
- **`java_server_3c.pcap`**: Unicast registration and multicast notifications between Java Server and 3 C Clients on loopback.
- **`c_server_interop.pcap`**: Unicast registrations and multicast notifications between C Server, 1 C Client, and 1 Java Client.

You can inspect these directly in Wireshark.

---

## CBOR Formatting Details

The informative response CBOR map matches the draft definition:
`{ 0: tp_info, ? 1: ph_req, ? 2: last_notif }`

### 1. `tp_info` (Key 0)
Formatted as `[ tpi_server, tpi_client, tpi_token ]`:
- Servers/clients are represented as Constrained Resource Identifiers (CRIs): `[ scheme-id, authority ]`.
- `scheme-id` is `-1` (CoAP).
- `authority` is `[ host-ip-bytes, ?port ]`.
- **IP Address**: Encoded as a byte string (`bstr`), e.g., `7F 00 00 01` (not a text string).
- **Port Omission**: If the port is default (`5683`), it is omitted.

### 2. `ph_req` (Key 1)
Serialized as a `bstr` representing the client's unicast registration GET request. The Java Californium parser expects this to include the standard CoAP UDP header (`[Ver/T/TKL = 0x40] [Code = 0x01] [MID = 0x00 0x00] [Observe Option = 0x60] [Uri-Path Option]`).

### 3. `last_notif` (Key 2)
Serialized as a `bstr` representing the initial multicast notification in transport-independent CoAP format (`[Code (0x45)] [Observe Option (0x61 0x01)] [Content-Format Option (0x60)] [0xFF payload marker] [Payload]`).

