# CoAP Multicast Observe Implementation in C

This repository contains a fully documented, runnable, and maintainable C implementation of the CoAP Multicast Observe mechanism based on the IETF draft `draft-ietf-core-observe-multicast-notifications`.

It is designed to interoperate with the Java reference implementation from the `adriankastrati/californium-thesis-work` repository (`multicast-notifications` branch) by matching its CBOR encoding, CoAP option formats, and protocol state machine.

## Prerequisites

The project requires the standard **libcoap** and **libcbor** libraries.

On macOS, you can install them via Homebrew:
```bash
brew install libcoap libcbor
```

## Compilation

Build both the client and server using the provided `Makefile`:
```bash
make
```
This generates the `coap_server` and `coap_client` binaries.

To clean up build artifacts:
```bash
make clean
```

## Running the Demo

### 1. Start the Server
Start the CoAP server listening on port `5683` (unicast) and broadcasting notifications to the multicast address `224.0.1.187:56830`:
```bash
./coap_server
```

You can optionally enable **standard OSCORE** protection for the unicast registration phase using the `-s` flag:
```bash
./coap_server -s
```

### 2. Start Multiple Clients
Open one or more terminal windows and start the clients:
```bash
./coap_client
```

If you enabled OSCORE on the server, you must also pass the `-s` flag to the clients:
```bash
./coap_client -s
```

### 3. Observe the Flow
- The client sends a unicast GET request with `Observe=0` to `coap://127.0.0.1:5683/obs`.
- The server responds with `5.03 Service Unavailable` containing the CBOR-serialized `tp_info` (which includes the multicast IP `224.0.1.187`, port `56830`, and the group Token `0x11223344`).
- The client decodes the CBOR payload, prints the configuration, joins the multicast group, and registers a phantom observation relation locally.
- Every 5 seconds, the server broadcasts a multicast CoAP `NON 2.05 Content` notification containing the updated state to `224.0.1.187:56830`.
- All running clients receive the multicast notification and print the updated state.

---

## Wireshark Traffic Analysis

To inspect the CoAP traffic:
1. Open Wireshark and start a capture on the loopback interface (`lo0` on macOS, `lo` on Linux).
2. Set the display filter to `coap`.
3. You will see:
   - **Unicast GET**: A `CON GET /obs` with the `Observe` option set to `0`. (Encrypted as OSCORE if `-s` is used).
   - **Informative Response**: A `5.03 Service Unavailable` response containing a CBOR payload mapped to Content-Format `120` (`application/informative-response+cbor`). (Encrypted as OSCORE if `-s` is used).
   - **Multicast Notifications**: Periodical `NON 2.05 Content` packets sent to the destination `224.0.1.187:56830` with Token `11223344` and the `Observe` option incremented for sequence tracking. Wireshark automatically dissects this as standard plain CoAP.

---

## Interoperability & CBOR Format Details

Per the Java reference implementation from the thesis work, the `tp_info` parameter is serialized as a CBOR Map where key `0` points to the `tp_info` array:
`{ 0: [ tpi_server, tpi_client, tpi_token ] }`

Where:
- `tpi_server` / `tpi_client` are formatted as Constrained Resource Identifiers (CRIs): `[ scheme-id, authority ]`.
- `scheme-id` is `-1` for `coap`.
- `authority` is `[ host-ip-bytes, ?port ]`.
- **IP Address**: The host IP address must be serialized as a CBOR **byte string** (`bstr`) of the raw IP bytes (e.g. `7F 00 00 01` for `127.0.0.1`), NOT a text string.
- **Port Omission**: If the port is the default CoAP port (`5683`), it is omitted from the authority array to save space.

The helper functions in `src/cbor_helper.c` implement this format precisely to achieve 100% binary-level compatibility with the Java codebase.
