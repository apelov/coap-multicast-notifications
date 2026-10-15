# Architecture

This repository implements [draft-ietf-core-observe-multicast-notifications-15](secure/draft-ietf-core-observe-multicast-notifications-15.txt)
("MO-15"): a server serves many Observe clients of one resource with a **single multicast
notification** instead of one unicast notification per client.

## Protocol in one page

1. A client registers by unicast (`GET` + `Observe: 0`). The server answers with a **5.03 informative
   response** (Content-Format 12, CBOR) carrying `tp_info` (the multicast group address and port,
   the server address, the token `T`), the phantom request `ph_req` and, if available,
   `last_notif` (the latest notification, so a late joiner is current at once).
2. The client joins the multicast group and from then on receives notifications there. Every
   notification is a non-confirmable `2.05` with the token `T`, sent from the server's own
   address and port (MO-15 §4.3), so the client can match it to the **phantom request** —
   a request the server never sends on the wire but both sides can reconstruct from `ph_req`.
3. The first registration creates the group observation and the phantom request; later clients
   only increment an observer counter. A stored latest notification is replicated verbatim to late
   joiners and refreshed when its Max-Age expires.

Secured profile (MO-15 §9, §10): the unicast leg is protected with **pairwise OSCORE** (RFC 8613);
the phantom request and the multicast notifications are protected with **Group OSCORE, group mode**
(draft-ietf-core-oscore-groupcomm-28), so all clients verify one signed message.

## Components

```
                    unsecured profile                     secured profile
 server   src/server.c                          src/sec/server_sec.c
 client   src/client.c                          src/sec/client_sec.c
 shared   src/cbor_helper.{c,h}  informative-response CBOR (tp_info, ph_req, last_notif)
          src/oscore_helper.{c,h}  pairwise OSCORE context setup (-s flag of the unsecured binaries)
          socket_hook.c            preload hook: sets SO_REUSEADDR/SO_REUSEPORT on bind() to port 56830 so several clients share a host
 secure   src/sec/sec_config.{c,h}  configuration file parser (contexts, group, credentials)
 core     src/sec/sec_group.{c,h}   phantom request and notification protection / verification (Group OSCORE)
          src/sec/sec_ti.{c,h}      transport-independent form of a message (MO-15 §4.2.2) <-> PDU
          src/sec/sec_ir.{c,h}      informative response encode / decode
          src/sec/sec_state.{c,h}   server state (observation, latest notification, Max-Age refresh)
                                    and client state (verified tuple, Response Number)
          src/sec/sec_debug.{c,h}   hex / diagnostic output
```

**Server.** `server_sec.c` registers the resource with libcoap, answers a registration with the
informative response (empty ACK first, then a separate confirmable 5.03 on the same token), and
a timer sends one notification per interval: the current representation is protected once
(`sec_notif_protect`), the datagram is multicast (`sec_mcast_send`), and the exact bytes in
transport-independent form become the stored `last_notif` (`sec_srv_latest_replace`) that is
handed to later registrants. The first stored notification (`INIT_NOTIF`, Observe 0) consumes one
Sender Sequence Number, so wire notifications continue at Observe 1, 2, 3.

**Client.** `client_sec.c` registers by unicast, decodes the informative response (`sec_ir_decode`),
rebuilds and **verifies** `ph_req` without replay check (MO-15 §9.3.1, `sec_phantom_verify`), stores
the verified tuple (kid, Partial IV, kid context), binds the notification endpoint and joins the
group. Each notification is checked: source equals the server address from the informative response
(§5.2 step 1), AEAD and countersignature verify against the stored tuple (`sec_notif_verify`), and a
Response Number window rejects replays independently of the Recipient replay window
(`sec_cli_accept`).

**External AAD.** `sec_build_e_aad` builds the `external_aad` of RFC 8613 §5.4 from the stored
phantom-request tuple. The OSCORE option's `options` element follows the Class I options of the
request; interop switches (`-C`) accept the empty-option variant used by the Java peer.

## Configuration

Both secure binaries are driven by one `key = value` file (`-c`). `docs/secure/examples/section10/`
reproduces the identifiers and sequence numbers of MO-15 §10; `docs/secure/examples/java-demo/`
matches the Californium demo. Keys cover: role, resource, group address/port, notification interval and
values, phantom token, one pairwise context per client (`pairwise.N.*`), and the Group OSCORE group
(`group.*`: Gid, secrets, algorithms, sender key and credential, recipients, Group Manager credential).
**All keys in the examples are public test fixtures; nothing is compiled into a binary.**

## libcoap and the patches

Group OSCORE comes from the `oscore_group` branch of libcoap. `make deps` clones the fork at a pinned
revision; `Makefile.secure` applies `patches/libcoap/*.patch` and builds a private static copy under
`build/` (a system libcoap is never modified):

| Patch | Purpose |
|---|---|
| 0001 | load CCS credentials for group members |
| 0002 | size the external AAD buffers for the real option lengths |
| 0003 | include the algorithm parameters in the external AAD |
| 0004 | hash handling when verifying the countersignature (Sign1) |
| 0005 | `coap_oscore_decrypt_pdu_ext()` with `COAP_OSCORE_DECRYPT_NO_REPLAY`: verify a request without replay check or state change (needed for `ph_req`) |
| 0006 | restore the replay state when verification fails |

The unsecured binaries use the system libcoap (`make vienna`).

## Tests

- `tests/sec/` — unit programs with TAP output, one per module: configuration, informative-response
  codec, AAD construction, notification protection, phantom request, `ph_req` verification, INIT_NOTIF
  and latest-notification handling. They load the example configurations and compare against fixed vectors.
- `tools/gosc_verify.py` — an independent Group OSCORE implementation written from the specification
  alone. It decrypts and verifies messages from a packet capture, and `tools/test_gosc_verify.py` tests it
  against the published RFC test vectors.

## Known deviations and compatibility switches

- RFC 9338 §3.3 omits `sign_protected` for the countersignature; the five-element
  `Countersign_structure` with an empty `sign_protected` is used because that is what the peer COSE
  library produces.
- The Content-Format of the informative response is not assigned yet (MO-15 §15.2); 12 is used.
- `-C` compatibility switches accept the Java peer's variants (UDP-wrapped `ph_req`, empty OSCORE option
  in the AAD, 2.04 outer code, any notification source port). All are off by default.
