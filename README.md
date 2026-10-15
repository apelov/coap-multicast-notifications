# CoAP multicast notifications for Observe — C implementation

A C implementation of [draft-ietf-core-observe-multicast-notifications-15](docs/secure/draft-ietf-core-observe-multicast-notifications-15.txt)
(Multicast Notifications for the Constrained Application Protocol Observe), built on libcoap:

- **Unsecured profile** (§1–§8): `coap_server`, `coap_client`.
- **Secured profile** (§9, §10): Pairwise OSCORE (RFC 8613) for registration, Group OSCORE
  (group mode, draft-ietf-core-oscore-groupcomm-28) for the phantom request and multicast
  notifications: `coap_server_sec`, `coap_client_sec`. This needs a libcoap fork with Group OSCORE
  support plus six small patches (`patches/libcoap/`), fetched and built privately under `build/`.

Status: research code written for interoperability testing against the draft authors' Java
(Californium) implementation. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design.

## Build and test

### Docker (any host, nothing to install)

```sh
docker build -t coap-observe-multicast .   # builds the patched libcoap and runs all tests
```

### Native

Prerequisites: a C compiler, `make`, `cmake`, `git`, `patch`, `pkg-config`, OpenSSL 3 and libcbor.

```sh
# macOS (Homebrew)
brew install cmake pkg-config libcbor openssl@3 libcoap
# Debian / Ubuntu
sudo apt-get install build-essential clang cmake pkg-config git patch libssl-dev libcbor-dev libcoap3-dev
```

```sh
make deps     # clone the libcoap fork at the pinned revision into build/
make test     # build the secure profile and run the unit tests (8 programs)
make          # build all four binaries
python3 tools/test_gosc_verify.py   # independent Group OSCORE verifier tests (needs python3-cryptography)
```

`make vienna` builds only the unsecured profile against your system libcoap (no `deps` needed);
`make secure` only the secured one. `make clean` / `make distclean` remove build outputs.

## Run

Unsecured, one server and N clients on this host:

```sh
make vienna && ./run_demo.sh 1
```

Secured, with the Section 10 test credentials (published fixtures, not secrets):

```sh
./coap_server_sec -c docs/secure/examples/section10/server.conf  -A 127.0.0.1 -p 5683
./coap_client_sec -c docs/secure/examples/section10/client1.conf -h 127.0.0.1 -p 5683 -I lo   # lo0 on macOS
```


## Layout

| Path | Content |
|---|---|
| `src/`, `src/sec/` | unsecured and secured server/client; `src/sec/` holds the §9 logic |
| `tests/sec/` | unit tests (TAP output) |
| `patches/libcoap/` | the six libcoap patches |
| `tools/gosc_verify.py` | independent Group OSCORE verifier (shares no code with the C side) |
| `docs/` | `ARCHITECTURE.md`; `docs/secure/` holds the example configurations and the IETF texts |

## Licence

MIT, see [`LICENSE`](LICENSE). Patches to libcoap are BSD-2-Clause; the IETF texts under
`docs/secure/*.txt` keep their own terms. Details in [`NOTICE`](NOTICE).
