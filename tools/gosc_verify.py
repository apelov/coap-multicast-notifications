#!/usr/bin/env python3
"""gosc_verify — an independent verifier for the secure Multicast Observe profile.

This tool re-implements, from the specification text alone, the protection that the C
implementation and the Java peer apply to the draft-15 §9/§10 scenario, and checks every
message it can observe on the wire against the requirement checklist
(the `R9.*` rows below).  It shares no code with the C implementation: the point is
to be an independent check of it.

What is implemented (all from the pinned drafts in `docs/secure/`):

  * MO-15  = draft-ietf-core-observe-multicast-notifications-15
  * GO-28  = draft-ietf-core-oscore-groupcomm-28
  * RFC 8613 (OSCORE), RFC 9338 (abbreviated countersignatures), RFC 9052/8152 (COSE),
    RFC 5869 (HKDF), RFC 8949 (CBOR), RFC 7252 (CoAP).

  * deterministic CBOR encode/decode (RFC 8949 §4.2 with the COSE narrowing, RFC 9338 §4)
  * CoAP message parse / option serialisation (RFC 7252 §3.1)
  * HKDF-SHA-256, AES-CCM-16-64-128 (COSE alg 10), ECDSA P-256/SHA-256 (ES256, alg -8)
  * OSCORE Security Context derivation (RFC 8613 §3.2.1)
  * Group OSCORE Signature Encryption Key (GO-28 §2.1.9) and
    modified Sender/Recipient Key + Common IV derivation (GO-28 §2.3)
  * AEAD nonce (RFC 8613 §5.2, with GO-28 §3.3 Step 4 for the group mode)
  * external_aad for OSCORE (RFC 8613 §5.4) and Group OSCORE (GO-28 §3.4, nine elements)
  * countersignature and its keystream (RFC 9338 §3.3, GO-28 §4.1/§4.2)
  * OSCORE header compression (RFC 8613 §6.1, GO-28 §4.1)
  * the transport-independent `ph_req` / `last_notif` encoding (MO-15 §4.2.2)

Inputs:

  * a packet capture (`.pcap`/`.pcapng`) or a JSON trace produced with `--emit-trace`
  * `--vector FILE` — the "Section-10-derived test vector" (`docs/secure/section10-vector.json`):
    every chosen input (master secrets, salts, algorithms, credentials, keys, IDs) plus the
    expected sequence.  All of it is a public test fixture.

The trace format removes the need for tshark: `--emit-trace` writes the decoded messages of a
capture as JSON, and the verifier consumes either that JSON or the pcap itself.

Exit status is 0 only when every observable conformance row passes.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import struct
import sys

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "gosc_verify: the 'cryptography' package is required (pip install cryptography)\n")
    raise

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

OSCORE_VERSION = 1
COAP_VERSION = 1

# RFC 8613 §6.1 option-value flag bits, then GO-28 §4.1 / §15.1.
FLAG_PARTIAL_IV_LEN_MASK = 0x07  # bits 1-3 counted from the LSB: Partial IV length n
FLAG_KID = 0x08                  # bit 4: 'kid' flag k
FLAG_KID_CONTEXT = 0x10          # bit 5: 'kid context' flag h
FLAG_GROUP = 0x20                # bit 6: the Group Flag, GO-28 §4.1 and §15.1 Table 1
FLAG_RESERVED_MASK = 0xC0        # bits 7-8, "SHALL be set to zero when not in use"

# COSE header parameter labels (RFC 9052 §3.1 / RFC 9338 §5.2).
LABEL_KID = 4
LABEL_PIV = 6
LABEL_KID_CONTEXT = 10
LABEL_COUNTERSIGNATURE0_V2 = 12

ALG_AES_CCM_16_64_128 = 10  # RFC 8152 §10.2
ALG_ES256 = -7  # RFC 9052 §4.1 — ECDSA w/ SHA-256, P-256
ALG_EDDSA = -8  # RFC 9052 §4.1 — EdDSA (Ed25519), used by this profile
HKDF_SHA256 = -10  # RFC 8152 §4.4

AEAD_KEY_LEN = 16  # AES-CCM-16-64-128
AEAD_TAG_LEN = 8
COMMON_IV_LEN = 13  # nonce length of AES-CCM-16-64-128
ES256_SIG_LEN = 64  # r || s, 32 octets each
EDDSA_SIG_LEN = 64  # RFC 8032 Ed25519 signature

# MO-15 §11 informative-response parameters.
IR_KEYS = {
    0: "tp_info", 1: "ph_req", 2: "last_notif", 3: "next_not_before", 4: "ending",
    5: "join_uri", 6: "sec_gp", 7: "as_uri", 8: "hkdf", 9: "cred_fmt",
    10: "gp_enc_alg", 11: "sign_alg", 12: "sign_params", 13: "gp_material",
    14: "srv_cred", 15: "srv_identifier", 16: "exi", 17: "exp",
}
# MO-15 §9.1 group-join signalling parameters; the deferred OPTIONAL set.
IR_JOIN_KEYS = (5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)

CODE_GET = 0x01
CODE_FETCH = 0x05
CODE_CONTENT = 0x45  # 2.05 — the multicast notification (MO-15 §10 Figure 7)
CODE_CHANGED = 0x44  # 2.04 — the outer Code of the unicast informative response.
# MO-15 §10 Figure 7 prints 2.05 there; RFC 8613 §4.2 makes it
# 2.04, the code for a response to a request that has changed the resource state.
CODE_SERVICE_UNAVAILABLE = 0xA3  # 5.03 — the informative response's inner Code (MO-15 §10)

OPT_OBSERVE = 6
OPT_URI_PATH = 11
OPT_CONTENT_FORMAT = 12
OPTION_NAMES = {
    1: "If-Match", 3: "Uri-Host", 4: "ETag", 5: "If-None-Match", 6: "Observe",
    7: "Uri-Port", 8: "Location-Path", 11: "Uri-Path", 12: "Content-Format",
    14: "Max-Age", 15: "Uri-Query", 17: "Accept", 20: "Location-Query", 35: "Proxy-Uri",
    39: "Proxy-Scheme", 60: "Size1", 9: "OSCORE",
}
CF_INFORMATIVE_RESPONSE = 12  # MO-15 §15.2 leaves it TBD; 12 is used by agreement


class VerifyError(Exception):
    """A message could not be processed.  The reason is the check that failed."""


# ---------------------------------------------------------------------------
# CBOR (RFC 8949) — deterministic encoding per RFC 8949 §4.2 and the COSE narrowing
# (RFC 9338 §4).  Small and self-contained on purpose: an independent implementation
# must not share an encoder with the code under test.
# ---------------------------------------------------------------------------

class CborError(Exception):
    pass


def _cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    if value < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", value)
    raise CborError("integer out of CBOR range")


def cbor_encode(value) -> bytes:
    """Deterministic CBOR.  Maps are key-sorted by encoded key length then bytewise."""
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -value - 1)
    if isinstance(value, bytes) or isinstance(value, bytearray):
        value = bytes(value)
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _cbor_head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        items = [(cbor_encode(k), cbor_encode(v)) for k, v in value.items()]
        # RFC 9052 §3.1: keys sorted first by length, then bytewise.
        items.sort(key=lambda kv: (len(kv[0]), kv[0]))
        return _cbor_head(5, len(items)) + b"".join(k + v for k, v in items)
    raise CborError("cannot encode %r" % (type(value),))


class _Untag:
    __slots__ = ("value", "tag")

    def __init__(self, value, tag):
        self.value = value
        self.tag = tag


def cbor_decode(data: bytes, offset: int = 0):
    """Decode one CBOR item.  Returns (value, next_offset).  Byte strings come back as
    bytes; tags surface as _Untag so the caller can accept or reject them explicitly."""
    if offset >= len(data):
        raise CborError("truncated CBOR")
    ib = data[offset]
    major, minor = ib >> 5, ib & 0x1F
    offset += 1
    if minor < 24:
        length, indefinite = minor, False
    elif minor == 24:
        length, indefinite = data[offset], False
        offset += 1
    elif minor == 25:
        length, indefinite = struct.unpack_from(">H", data, offset)[0], False
        offset += 2
    elif minor == 26:
        length, indefinite = struct.unpack_from(">I", data, offset)[0], False
        offset += 4
    elif minor == 27:
        length, indefinite = struct.unpack_from(">Q", data, offset)[0], False
        offset += 8
    elif minor == 31:
        length, indefinite = None, True
    else:
        raise CborError("reserved CBOR additional information %d" % minor)

    if major == 0:
        return length, offset
    if major == 1:
        return -1 - length, offset
    if major in (2, 3):
        if indefinite:
            raise CborError("indefinite-length strings not accepted (RFC 9052 §3.1)")
        end = offset + length
        if end > len(data):
            raise CborError("truncated CBOR byte/text string")
        raw = data[offset:end]
        if major == 2:
            return bytes(raw), end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError:
            raise CborError("invalid UTF-8 in CBOR text string")
    if major == 4:
        out = []
        if indefinite:
            while data[offset] != 0xFF:
                item, offset = cbor_decode(data, offset)
                out.append(item)
            return out, offset + 1
        for _ in range(length):
            item, offset = cbor_decode(data, offset)
            out.append(item)
        return out, offset
    if major == 5:
        out = {}
        if indefinite:
            while data[offset] != 0xFF:
                key, offset = cbor_decode(data, offset)
                val, offset = cbor_decode(data, offset)
                out[key] = val
            return out, offset + 1
        for _ in range(length):
            key, offset = cbor_decode(data, offset)
            val, offset = cbor_decode(data, offset)
            if key in out:
                raise CborError("duplicate CBOR map key")
            out[key] = val
        return out, offset
    if major == 6:
        item, offset = cbor_decode(data, offset)
        return _Untag(item, length), offset
    if major == 7:
        if minor == 20:
            return False, offset
        if minor == 21:
            return True, offset
        if minor == 22:
            return None, offset
        if minor == 23:
            return "undefined", offset
        if minor == 25:
            return ("half", struct.unpack_from(">H", data, offset - 2)[0]), offset
        if minor == 26:
            return ("float", struct.unpack_from(">f", data, offset - 4)[0]), offset
        if minor == 27:
            return ("float", struct.unpack_from(">d", data, offset - 8)[0]), offset
        raise CborError("unsupported simple/float value %d" % minor)
    raise CborError("unreachable CBOR major type %d" % major)


def cbor_decode_all(data: bytes):
    items = []
    offset = 0
    while offset < len(data):
        item, offset = cbor_decode(data, offset)
        items.append(item)
    return items


def cbor_is_canonical(data: bytes) -> bool:
    """True when re-encoding the decoded item reproduces `data` byte for byte."""
    try:
        items = cbor_decode_all(data)
    except CborError:
        return False
    if len(items) != 1:
        return False
    try:
        return cbor_encode(items[0]) == data
    except CborError:
        return False


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) and COSE algorithm parameters
# ---------------------------------------------------------------------------

def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int, alg: int = HKDF_SHA256) -> bytes:
    if alg != HKDF_SHA256:
        raise VerifyError("only HKDF-SHA-256 (COSE alg -10) is implemented")
    digest = hashlib.sha256
    hash_len = digest().digest_size
    if length > 255 * hash_len:
        raise VerifyError("HKDF output too long")
    # RFC 8613 §3.2.1: an absent salt is the empty byte string, which RFC 5869 §2.2
    # defines as HashLen zero octets.
    prk = hmac.new(bytes(hash_len) if not salt else salt, ikm, digest).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), digest).digest()
        out += block
        counter += 1
    return out[:length]


def _alg_len(alg) -> int:
    """Key length of an AEAD / Group Encryption Algorithm, in bytes."""
    if alg == ALG_AES_CCM_16_64_128:
        return AEAD_KEY_LEN
    if isinstance(alg, str) and alg.startswith("A128"):
        return 16
    raise VerifyError("unsupported algorithm %r for key length" % (alg,))


def _nonce_len(alg) -> int:
    if alg == ALG_AES_CCM_16_64_128:
        return COMMON_IV_LEN
    if isinstance(alg, str) and alg.startswith("A128"):
        return 12
    raise VerifyError("unsupported algorithm %r for nonce length" % (alg,))


# ---------------------------------------------------------------------------
# CoAP (RFC 7252)
# ---------------------------------------------------------------------------

def parse_options(raw: bytes):
    """Decode a serialised CoAP option sequence into [(number, value_bytes)]."""
    out, number, offset = [], 0, 0
    while offset < len(raw):
        byte = raw[offset]
        offset += 1
        delta, length = byte >> 4, byte & 0x0F
        if delta == 15 or length == 15:
            raise VerifyError("reserved CoAP option delta/length 15")
        number += delta
        end = offset + length
        if end > len(raw):
            raise VerifyError("truncated CoAP option")
        out.append((number, raw[offset:end]))
        offset = end
    return out


def serialize_options(options) -> bytes:
    """Encode [(number, value_bytes)] as the wire octets, preserving the given order."""
    out = bytearray()
    last = 0
    for number, value in options:
        number, value = int(number), bytes(value)
        delta = number - last
        if delta < 0:
            raise VerifyError("CoAP options not in ascending order")
        if delta > 13 or len(value) > 13:
            raise VerifyError("extended CoAP option delta/length not implemented")
        out.append((delta << 4) | len(value))
        out += value
        last = number
    return bytes(out)


def parse_uint(value: bytes) -> int:
    return int.from_bytes(value, "big") if value else 0


def encode_uint(number: int) -> bytes:
    """Minimal-length uint option value (RFC 7252 §3.2)."""
    if number == 0:
        return b""
    return number.to_bytes((number.bit_length() + 7) // 8, "big")


class CoapMessage:
    """A CoAP message: header, token, options, payload."""

    __slots__ = ("mtype", "code", "mid", "token", "options", "payload")

    def __init__(self, mtype, code, mid, token, options, payload):
        self.mtype, self.code, self.mid = mtype, code, mid
        self.token, self.options, self.payload = token, options, payload

    @property
    def is_request(self):
        return 0x01 <= self.code <= 0x1F

    def opt(self, number):
        for num, value in self.options:
            if num == number:
                return value
        return None

    def opts(self, number):
        return [v for n, v in self.options if n == number]

    def oscore_option(self):
        for num, value in self.options:
            if num == 9:
                return value
        return None

    def __repr__(self):
        c = "%d.%02d" % (self.code >> 5, self.code & 0x1F)
        return "<CoAP %s %s mid=%d tok=%s opts=%s payload=%dB>" % (
            ["CON", "NON", "ACK", "RST"][self.mtype] if self.mtype < 4 else "?",
            c, self.mid, self.token.hex(), self.options, len(self.payload))


def parse_coap(data: bytes) -> CoapMessage:
    """Parse a complete CoAP message (RFC 7252 §3)."""
    if len(data) < 4:
        raise VerifyError("CoAP message shorter than 4 bytes")
    first = data[0]
    if first >> 6 != COAP_VERSION:
        raise VerifyError("not CoAP over UDP (version %d)" % (first >> 6))
    mtype, tkl = (first >> 4) & 0x03, first & 0x0F  # RFC 7252 §3: Ver | T | TKL
    if tkl > 8:
        raise VerifyError("invalid token length %d" % tkl)
    code, mid = data[1], struct.unpack_from(">H", data, 2)[0]
    if 4 + tkl > len(data):
        raise VerifyError("truncated CoAP token")
    token, offset = data[4:4 + tkl], 4 + tkl
    rest = data[offset:]
    payload = b""
    if b"\xff" in rest:  # the Payload Marker terminates the option sequence (RFC 7252 §3)
        index = rest.index(b"\xff")
        payload = rest[index + 1:]
        rest = rest[:index]
    return CoapMessage(mtype, code, mid, token, parse_options(rest), payload)


def serialize_coap(msg: CoapMessage, with_type_code_mid=True) -> bytes:
    out = bytearray()
    if with_type_code_mid:
        out.append((COAP_VERSION << 6) | (msg.mtype << 4) | len(msg.token))
        out.append(msg.code)
        out += struct.pack(">H", msg.mid)
    out += msg.token
    out += serialize_options(msg.options)
    if msg.payload:
        out.append(0xFF)  # the Payload Marker (RFC 7252 §3)
        out += msg.payload
    return bytes(out)


class InnerMessage:
    """The transport-independent plaintext of an OSCORE-protected message
    (RFC 8613 §5.3, Figure 9; identical in shape to MO-15 §4.2.2): Code | options |
    0xff | payload, with no UDP header, MID or Token framing."""

    __slots__ = ("code", "options", "payload")

    def __init__(self, code, options, payload=b""):
        self.code, self.options, self.payload = code, options, payload

    def opt(self, number):
        for num, value in self.options:
            if num == number:
                return value
        return None

    def opts(self, number):
        return [v for n, v in self.options if n == number]

    def as_transport_independent(self) -> bytes:
        return serialize_transport_independent(self.code, self.options, self.payload)

    def as_coap(self, mtype, mid, token) -> CoapMessage:
        return CoapMessage(mtype, self.code, mid, token, list(self.options), self.payload)

    @property
    def is_request(self):
        return 0x01 <= self.code <= 0x1F

    def __repr__(self):
        return "<inner %d.%02d opts=%s payload=%dB>" % (
            self.code >> 5, self.code & 0x1F, self.options, len(self.payload))


# ---------------------------------------------------------------------------
# OSCORE header compression (RFC 8613 §6.1, Group Flag per GO-28 §4.1 / §15.1)
# ---------------------------------------------------------------------------

class OscodeOption:
    """The decoded OSCORE Option value (RFC 8613 §6.1)."""

    __slots__ = ("raw", "piv", "kid_context", "kid", "group", "n", "k", "h")

    def __init__(self, raw, piv, kid_context, kid, group):
        self.raw, self.piv, self.kid_context, self.kid, self.group = (
            raw, piv, kid_context, kid, group)
        self.n = len(piv)
        self.k = 1 if kid is not None else 0
        self.h = 1 if kid_context is not None else 0

    def __repr__(self):
        return ("<OSCORE group=%d n=%d piv=%s kid_ctx=%s kid=%s>"
                % (self.group, self.n,
                   self.piv.hex() if self.piv else "-",
                   self.kid_context.hex() if self.kid_context is not None else "-",
                   self.kid.hex() if self.kid is not None else "-"))


def parse_oscore_option(raw: bytes) -> OscodeOption:
    if not raw:
        # A zero-length OSCORE Option value is legal (RFC 8613 §6.1): no Partial IV, no
        # 'kid', no 'kid context'.  It is what MO-15 §10 Figure 7 shows on the unicast
        # informative responses ("OSCORE: - (empty)").
        return OscodeOption(b"", b"", None, None, False)
    flags = raw[0]
    if flags & FLAG_RESERVED_MASK:
        raise VerifyError("reserved OSCORE flag bits set (0x%02x)" % flags)
    n = flags & FLAG_PARTIAL_IV_LEN_MASK
    if n in (6, 7):
        raise VerifyError("reserved Partial IV length %d" % n)
    offset = 1
    if offset + n > len(raw):
        raise VerifyError("OSCORE Option truncated in the Partial IV")
    piv = raw[offset:offset + n]
    offset += n
    kid_context = None
    if flags & FLAG_KID_CONTEXT:
        if offset >= len(raw):
            raise VerifyError("OSCORE Option truncated before the kid context length")
        s = raw[offset]
        offset += 1
        if offset + s > len(raw):
            raise VerifyError("OSCORE Option truncated in the kid context")
        kid_context = raw[offset:offset + s]
        offset += s
    kid = raw[offset:] if (flags & FLAG_KID) else None
    if (flags & FLAG_KID) and not kid:
        raise VerifyError("kid flag set with empty kid")
    if not (flags & FLAG_KID) and offset != len(raw):
        raise VerifyError("OSCORE Option has trailing bytes without the kid flag")
    return OscodeOption(raw, piv, kid_context, kid, (flags & FLAG_GROUP) != 0)


def compress_oscore_option(piv: bytes, kid_context, kid, group: bool) -> bytes:
    """Build the OSCORE Option value (RFC 8613 §6.1 with the GO-28 Group Flag).

    When there is nothing to carry and the Group Flag is 0, the option value is empty:
    RFC 8613 §6.3 example 4 prints "Flag byte: 0x00 (1 byte), Option Value: 0x (0 bytes)",
    i.e. a zero-length OSCORE Option, which is what MO-15 §10 Figure 7 shows on the
    unicast informative responses ("OSCORE: - (empty)").
    """
    if len(piv) > 5:
        raise VerifyError("Partial IV longer than 5 bytes")
    if not piv and kid_context is None and kid is None and not group:
        return b""
    flags = len(piv) & FLAG_PARTIAL_IV_LEN_MASK
    if kid is not None:
        flags |= FLAG_KID
    if kid_context is not None:
        flags |= FLAG_KID_CONTEXT
    if group:
        flags |= FLAG_GROUP
    out = bytearray([flags]) + piv
    if kid_context is not None:
        out.append(len(kid_context))
        out += kid_context
    if kid is not None:
        out += kid
    return bytes(out)


def compress_cose(protected: bytes, unprotected: dict, ciphertext: bytes,
                  encrypted_countersignature: bytes = b"", group: bool = False):
    """Compress a COSE_Encrypt0 object into the OSCORE Option value and the payload.

    RFC 8613 §6.1 and §6.2, with the two Group OSCORE additions of GO-28 §4.1: the Group
    Flag is set in group mode, and the payload is the ciphertext concatenated with the
    encrypted countersignature.

    Returns (oscore_option_value, payload).  The published examples of RFC 8613 §6.3 and
    GO-28 §4.3 are exactly this function's output, and `tools/test_gosc_verify.py` checks
    it against them.
    """
    kid = unprotected.get(LABEL_KID)
    piv = unprotected.get(LABEL_PIV, b"")
    kid_context = unprotected.get(LABEL_KID_CONTEXT)
    option = compress_oscore_option(piv, kid_context, kid, group)
    return option, ciphertext + encrypted_countersignature


# ---------------------------------------------------------------------------
# nonces (RFC 8613 §5.2 for the pairwise mode; GO-28 §3.3 for the group mode)
# ---------------------------------------------------------------------------

def nonce_pairwise(piv: bytes, id_piv: bytes, common_iv: bytes) -> bytes:
    n = len(common_iv)
    if n < 7:
        raise VerifyError("OSCORE requires a nonce of at least 7 bytes (RFC 8613 §5.2)")
    padded_piv = bytes(5 - len(piv)) + piv            # step 1: left-pad PIV to 5 bytes
    padded_id = bytes(n - 6 - len(id_piv)) + id_piv   # step 2: left-pad ID_PIV
    seed = bytes([len(id_piv)]) + padded_id + padded_piv  # step 3
    return bytes(a ^ b for a, b in zip(seed, common_iv))  # step 4


def nonce_group(piv: bytes, id_piv: bytes, common_iv: bytes, nonce_len: int) -> bytes:
    """GO-28 §3.3.

    "The nonce is constructed like in OSCORE, with the difference that Step 4 in Section 5.2
    of [RFC8613] is replaced with: 4. and then XOR with X bytes from the Common IV's start,
    where X is the length in bytes of the nonce."

    RFC 8613 §5.2 steps 1-3 are therefore kept, ID_PIV included, and only the final XOR
    changes: the Common IV may be longer than the nonce (GO-28 §2.1.4 takes the greatest
    nonce length among the AEAD and Group Encryption Algorithms), and then only its first
    `nonce_len` bytes are used.  With a Common IV of exactly the nonce length — the case
    here, since both algorithms are AES-CCM-16-64-128 with a 13-byte nonce — this is
    byte-for-byte identical to RFC 8613 §5.2.
    """
    if nonce_len < 7:
        raise VerifyError("OSCORE requires a nonce of at least 7 bytes (RFC 8613 §5.2)")
    padded_piv = bytes(5 - len(piv)) + piv
    padded_id = bytes(nonce_len - 6 - len(id_piv)) + id_piv
    seed = bytes([len(id_piv)]) + padded_id + padded_piv
    iv = common_iv[:nonce_len]
    if len(iv) != nonce_len:
        raise VerifyError("Common IV shorter than the nonce")
    return bytes(a ^ b for a, b in zip(seed, iv))


# ---------------------------------------------------------------------------
# Additional Authenticated Data
# ---------------------------------------------------------------------------

def aad_oscore(request_kid: bytes, request_piv: bytes, options: bytes, alg_aead) -> bytes:
    """external_aad for plain OSCORE (RFC 8613 §5.4)."""
    return cbor_encode([OSCORE_VERSION, [alg_aead], request_kid, request_piv, options])


def aad_group(request_kid, request_piv, options, request_kid_context, oscore_option,
              sender_cred, gm_cred, alg_aead, alg_group_enc, alg_signature,
              alg_pairwise_key_agreement) -> bytes:
    """external_aad for Group OSCORE (GO-28 §3.4, Figure 2).

    All nine elements are present.  An algorithm that is not set in the Common Context is
    the CBOR simple value null (0xf6), which `cbor_encode(None)` produces.
    """
    return cbor_encode([
        OSCORE_VERSION,
        [alg_aead, alg_group_enc, alg_signature, alg_pairwise_key_agreement],
        request_kid, request_piv, options, request_kid_context, oscore_option,
        sender_cred, gm_cred,
    ])


def countersign_structure(context: str, body_protected: bytes, external_aad: bytes,
                          payload: bytes, sign_protected: bytes = b"",
                          include_sign_protected: bool = False) -> bytes:
    """The ToBeSigned of an abbreviated countersignature (RFC 9338 §3.3).

    `include_sign_protected` selects the five-element form.  RFC 9338 §3.3 marks
    `sign_protected` optional and describes it as omitted for the Countersignature0V2
    attribute; the COSE libraries used by this project emit the five-element form with an
    empty `sign_protected` (a known inconsistency with RFC 9338 §3.3).  Both forms are tried by the verifier and the one that verifies is
    reported, so the deviation is visible rather than silently absorbed.
    """
    fields = [context, body_protected]
    if include_sign_protected:
        fields.append(sign_protected or b"")
    fields += [external_aad, payload]
    return cbor_encode(fields)


# ---------------------------------------------------------------------------
# Security contexts
# ---------------------------------------------------------------------------

class PairwiseContext:
    """An RFC 8613 Security Context (MO-15 §9 unicast leg)."""

    def __init__(self, master_secret: bytes, master_salt: bytes,
                 aead_alg=ALG_AES_CCM_16_64_128, hkdf_alg=HKDF_SHA256,
                 sender_id: bytes = b"", recipient_id: bytes = b"",
                 id_context=None, label: str = ""):
        self.master_secret, self.master_salt = master_secret, master_salt
        self.aead_alg, self.hkdf_alg = aead_alg, hkdf_alg
        self.sender_id, self.recipient_id, self.id_context = sender_id, recipient_id, id_context
        self.label = label
        self.sender_key = self._derive(sender_id, "Key", _alg_len(aead_alg))
        self.recipient_key = self._derive(recipient_id, "Key", _alg_len(aead_alg))
        self.common_iv = self._derive(b"", "IV", _nonce_len(aead_alg))

    def _derive(self, ident: bytes, kind: str, length: int) -> bytes:
        # RFC 8613 §3.2.1.
        info = cbor_encode([ident, self.id_context, self.aead_alg, kind, length])
        return hkdf(self.master_salt, self.master_secret, info, length, self.hkdf_alg)

    def nonce(self, piv: bytes, id_piv: bytes) -> bytes:
        return nonce_pairwise(piv, id_piv, self.common_iv)


class GroupContext:
    """A Group OSCORE Common Context (GO-28 §2.3) and one Sender Context / Recipient
    Context.  This is the MO-15 §9.2 group leg."""

    def __init__(self, master_secret: bytes, master_salt: bytes, gid: bytes,
                 aead_alg=ALG_AES_CCM_16_64_128, hkdf_alg=HKDF_SHA256,
                 group_enc_alg=ALG_AES_CCM_16_64_128, signature_alg=ALG_EDDSA,
                 pairwise_key_agreement_alg=None, sender_cred=b"", gm_cred=b"",
                 sender_id: bytes = b"", recipient_id: bytes = b"",
                 sender_private_key=None, recipient_pubkey=None, label: str = ""):
        self.master_secret, self.master_salt, self.gid = master_secret, master_salt, gid
        self.aead_alg, self.hkdf_alg = aead_alg, hkdf_alg
        self.group_enc_alg = group_enc_alg
        self.signature_alg = signature_alg
        self.pairwise_key_agreement_alg = pairwise_key_agreement_alg
        self.sender_cred, self.gm_cred = sender_cred, gm_cred
        self.sender_id, self.recipient_id = sender_id, recipient_id
        self.sender_private_key = sender_private_key
        self.recipient_pubkey = recipient_pubkey
        self.label = label

        # GO-28 §2.3: when the Group Encryption Algorithm is set, the 'alg_aead' element of
        # the info array is the Group Encryption Algorithm, not the AEAD Algorithm.
        self.derivation_alg = group_enc_alg if group_enc_alg is not None else aead_alg
        key_len = _alg_len(self.derivation_alg)
        self.sender_key = self._derive(sender_id, "Key", key_len)
        self.recipient_key = self._derive(recipient_id, "Key", key_len)
        self.common_iv = self._derive(b"", "IV", _nonce_len(self.derivation_alg))
        # GO-28 §2.1.9: same derivation as Sender/Recipient Keys with an empty 'id', the
        # Group Encryption Algorithm in 'alg_aead', type "SEKey" and L = its key length.
        self.signature_encryption_key = self._derive(
            b"", "SEKey", key_len, alg=self.group_enc_alg)

    def _derive(self, ident: bytes, kind: str, length: int, alg=None) -> bytes:
        info = cbor_encode([ident, self.gid, alg if alg is not None else self.derivation_alg,
                            kind, length])
        return hkdf(self.master_salt, self.master_secret, info, length, self.hkdf_alg)

    def nonce(self, piv: bytes, id_piv: bytes) -> bytes:
        return nonce_group(piv, id_piv, self.common_iv, _nonce_len(self.derivation_alg))

    def keystream(self, piv: bytes, id_piv: bytes, is_request: bool, length: int) -> bytes:
        """KEYSTREAM for the encrypted countersignature (GO-28 §4.2)."""
        info = cbor_encode([id_piv, self.gid, bool(is_request), length])
        return hkdf(piv, self.signature_encryption_key, info, length, self.hkdf_alg)

    def aad(self, request_kid, request_piv, options, request_kid_context, oscore_option):
        """GO-28 §3.4 external_aad, using this context's Common Context values verbatim —
        including the CBOR null for an algorithm that is not set."""
        return aad_group(request_kid, request_piv, options, request_kid_context,
                         oscore_option, self.sender_cred, self.gm_cred,
                         self.aead_alg, self.group_enc_alg, self.signature_alg,
                         self.pairwise_key_agreement_alg)


# ---------------------------------------------------------------------------
# AEAD and countersignature primitives
# ---------------------------------------------------------------------------

def enc_structure(external_aad: bytes, protected: bytes = b"") -> bytes:
    """The AAD actually handed to the AEAD (RFC 9052 §5.1):
    `Enc_structure = [ "Encrypt0", protected, external_aad ]`.

    `external_aad` is already the bstr-wrapped array of RFC 8613 §5.4 / GO-28 §3.4; the
    countersignature instead signs that value directly (RFC 9338 §3.3).
    """
    return cbor_encode(["Encrypt0", protected, external_aad])


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, external_aad: bytes,
                 tag_len=AEAD_TAG_LEN):
    return AESCCM(key, tag_length=tag_len).encrypt(
        nonce, plaintext, enc_structure(external_aad))


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, external_aad: bytes,
                 tag_len=AEAD_TAG_LEN):
    return AESCCM(key, tag_length=tag_len).decrypt(
        nonce, ciphertext, enc_structure(external_aad))


def es256_sign(private_key, data: bytes) -> bytes:
    """RFC 9052 §4.1: ECDSA over P-256 with SHA-256, r || s, 32 octets each."""
    der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def es256_verify(public_key, data: bytes, signature: bytes) -> bool:
    if len(signature) != ES256_SIG_LEN:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        public_key.verify(asym_utils.encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def eddsa_sign(private_key, data: bytes) -> bytes:
    """RFC 9052 §4.1 (EdDSA, RFC 8032 Ed25519): the 64-octet signature."""
    return private_key.sign(data)


def eddsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    if len(signature) != EDDSA_SIG_LEN:
        return False
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def signature_length(alg) -> int:
    if alg == ALG_EDDSA:
        return EDDSA_SIG_LEN
    if alg == ALG_ES256:
        return ES256_SIG_LEN
    raise VerifyError("unsupported Signature Algorithm %r" % (alg,))


def sign(alg, private_key, data: bytes) -> bytes:
    if alg == ALG_EDDSA:
        return eddsa_sign(private_key, data)
    if alg == ALG_ES256:
        return es256_sign(private_key, data)
    raise VerifyError("unsupported Signature Algorithm %r" % (alg,))


def signature_verify(alg, public_key, data: bytes, signature: bytes) -> bool:
    if alg == ALG_EDDSA:
        return eddsa_verify(public_key, data, signature)
    if alg == ALG_ES256:
        return es256_verify(public_key, data, signature)
    raise VerifyError("unsupported Signature Algorithm %r" % (alg,))


def public_key_from_credential_x(alg, x: bytes):
    """Build the verification key from a COSE_Key carrying only the x coordinate.

    For Ed25519 (COSE EdDSA / Ed25519, COSE key label -25) the y coordinate is the fixed
    value 1 and is omitted; for ES256 (COSE key label -25) the y coordinate must be present,
    so an Ed25519-shaped key is not usable for ES256.  `x` is what the credential carries.
    """
    if alg == ALG_EDDSA:
        return Ed25519PublicKey.from_public_bytes(x)
    if alg == ALG_ES256:
        raise VerifyError("ES256 credentials must carry both x and y")
    raise VerifyError("unsupported Signature Algorithm %r" % (alg,))


def private_key_from_seed(alg, seed: bytes):
    """The private key from the 32-byte seed form used by the shipped profiles."""
    if alg == ALG_EDDSA:
        return Ed25519PrivateKey.from_private_bytes(seed)
    if alg == ALG_ES256:
        return ec.derive_private_key(int.from_bytes(seed, "big"), ec.SECP256R1())
    raise VerifyError("unsupported Signature Algorithm %r" % (alg,))


# ---------------------------------------------------------------------------
# message verification
# ---------------------------------------------------------------------------

class VerifyResult:
    """The outcome of verifying one protected message."""

    def __init__(self, ok, note="", plaintext=None, oscore=None, signature_form=None):
        self.ok, self.note = ok, note
        self.plaintext = plaintext
        self.oscore = oscore
        self.signature_form = signature_form


def verify_pairwise(msg: CoapMessage, ctx: PairwiseContext, request_kid=None,
                    request_piv=b"", options: bytes = b"", id_context=None, id_piv=None,
                    key=None):
    """Verify and decrypt a plain OSCORE (RFC 8613 §8.2 / §8.4) protected message.

    `request_kid` / `request_piv` / `options` / `id_context` come from the associated
    request; for a request they are its own OSCORE Option fields.

    `id_piv` is the Sender ID of the endpoint that generated the Partial IV used for this
    message (RFC 8613 §5.2 Step 2).  A response that carries no Partial IV reuses the
    request's, and the request's Partial IV was generated by the client — so ID_PIV is the
    *client's* Sender ID, which is the request 'kid'.  That is the default.

    `key` selects the key: the Recipient Key (the default, i.e. this endpoint is receiving)
    or, for recomputing a message this endpoint itself sent, its Sender Key.
    """
    raw = msg.oscore_option()
    if raw is None:
        raise VerifyError("message carries no OSCORE Option")
    osc = parse_oscore_option(raw)
    if osc.group:
        raise VerifyError("Group Flag set on a message that must use plain OSCORE")
    if request_kid is None:
        request_kid = osc.kid if osc.kid is not None else b""
        request_piv = osc.piv
    if id_piv is None:
        id_piv = request_kid
    if id_context is None:
        id_context = b"" if ctx.id_context is None else ctx.id_context
    # RFC 8613 §5.2: "If the Partial IV is not present in a response, the nonce from the
    # request is used."  MO-15 §10 Figure 7 shows exactly that on the unicast informative
    # responses ("OSCORE: - (empty)").
    nonce_piv = osc.piv if osc.piv else request_piv
    external_aad = aad_oscore(request_kid, request_piv, options, ctx.aead_alg)
    nonce = ctx.nonce(nonce_piv, id_piv)
    key = ctx.recipient_key if key is None else key
    try:
        plaintext = aead_decrypt(key, nonce, msg.payload, external_aad)
    except InvalidTag:
        return VerifyResult(False, "AEAD verification failed (RFC 8613 §5.1)")
    return VerifyResult(True, plaintext=InnerMessage(*parse_transport_independent(plaintext)),
                        oscore=osc)


def verify_group(msg: CoapMessage, ctx: GroupContext, request_kid, request_piv,
                 request_kid_context, options: bytes = b"", id_piv=None,
                 is_request=None, signer_pubkey=None, oscore_option_override=None):
    """Verify a Group OSCORE group-mode message (GO-28 §7.2 request / §7.4 response).

    `request_kid`, `request_piv` and `request_kid_context` are the values of the *request*
    (MO-15 §9.2.3 / §9.3.2 freeze them to the phantom request's OSCORE Option).  `options`
    are the Class I options of the message as sent.  `id_piv` is the Sender ID that generated
    the PIV (GO-28 §4.2), which is the response's own 'kid' when present.
    """
    raw = msg.oscore_option()
    if raw is None:
        raise VerifyError("message carries no OSCORE Option")
    osc = parse_oscore_option(raw)
    if not osc.group:
        raise VerifyError("Group Flag not set (GO-28 §4.1: MUST be 1 in group mode)")
    if is_request is None:
        is_request = msg.is_request
    if id_piv is None:
        id_piv = osc.kid if osc.kid is not None else ctx.sender_id
    if oscore_option_override is not None:
        option_bytes = oscore_option_override
    else:
        # GO-28 §3.4: 'OSCORE_option' is the *actual finalized value* of this message's
        # OSCORE Option.  Using h'' instead is a known Java peer deviation.
        option_bytes = raw

    external_aad = ctx.aad(request_kid, request_piv, options, request_kid_context,
                           option_bytes)
    # RFC 8613 §5.2: a response without its own Partial IV reuses the request's nonce.
    nonce_piv = osc.piv if osc.piv else request_piv
    nonce = ctx.nonce(nonce_piv, id_piv)

    sig_len = signature_length(ctx.signature_alg)
    payload = msg.payload
    if len(payload) < sig_len:
        return VerifyResult(False, "payload too short to carry ciphertext + countersignature")
    ciphertext, enc_signature = payload[:-sig_len], payload[-sig_len:]

    pub = signer_pubkey if signer_pubkey is not None else ctx.recipient_pubkey
    signature_form = None
    if pub is not None:
        keystream = ctx.keystream(osc.piv, id_piv, is_request, sig_len)
        signature = bytes(a ^ b for a, b in zip(enc_signature, keystream))
        for include_sign_protected in (True, False):
            to_be_signed = countersign_structure(
                "CounterSignature0", b"", external_aad, ciphertext,
                include_sign_protected=include_sign_protected)
            if signature_verify(ctx.signature_alg, pub, to_be_signed, signature):
                signature_form = ("5-element" if include_sign_protected else "4-element")
                break
        if signature_form is None:
            return VerifyResult(False, "countersignature verification failed (GO-28 §7.4 "
                                       "Step 5)", oscore=osc)

    try:
        plaintext = aead_decrypt(ctx.recipient_key, nonce, ciphertext, external_aad)
    except InvalidTag:
        return VerifyResult(False, "AEAD verification failed (GO-28 §7.4 Step 5)", oscore=osc)
    return VerifyResult(True,
                        plaintext=InnerMessage(*parse_transport_independent(plaintext)),
                        oscore=osc, signature_form=signature_form)


def protect_group(ctx: GroupContext, inner: InnerMessage, piv: int, kid: bytes,
                  is_request: bool, request_kid: bytes, request_piv: bytes,
                  request_kid_context, outer_options, key=None, signature=None,
                  option_bytes=None, mtype=None, token=b"", mid=0) -> bytes:
    """Compute a group-mode protected payload from declared inputs.

    Returns the OSCORE Option value and the payload (ciphertext || encrypted
    countersignature).  This is the generator side used by the tamper tests and by the
    Section-10 vector: recomputing a message from the published inputs turns "the observed
    bytes do not verify" into "the observed bytes are not what the draft prescribes", and
    lets one field be varied while everything else stays correct.
    """
    key = key if key is not None else ctx.recipient_key
    piv_bytes = encode_uint(piv)
    option = option_bytes if option_bytes is not None else compress_oscore_option(
        piv_bytes, request_kid_context, kid, True)
    external_aad = ctx.aad(request_kid, request_piv, serialize_options(outer_options),
                           request_kid_context, option)
    ciphertext = aead_encrypt(key, ctx.nonce(piv_bytes, kid),
                              inner.as_transport_independent(), external_aad)
    if signature is None:
        signature = group_countersign(ctx, ciphertext, external_aad, is_request, kid)
    keystream = ctx.keystream(piv_bytes, kid, is_request, signature_length(ctx.signature_alg))
    enc_signature = bytes(a ^ b for a, b in zip(signature, keystream))
    if mtype is None:
        mtype = 0 if is_request else 1
    return option, ciphertext + enc_signature


def group_countersign(ctx: GroupContext, ciphertext: bytes, external_aad: bytes,
                      is_request: bool, id_piv: bytes, include_sign_protected=True) -> bytes:
    """The plain countersignature SIGNATURE over the COSE object (RFC 9338 §3.3 as used by
    GO-28 §3.1).  `include_sign_protected` selects the five-element Countersign_structure;
    `verify_group` accepts either and reports which one matched."""
    to_be_signed = countersign_structure(
        "CounterSignature0", b"", external_aad, ciphertext,
        include_sign_protected=include_sign_protected)
    if ctx.sender_private_key is None:
        raise VerifyError("no private key: cannot produce a countersignature")
    return sign(ctx.signature_alg, ctx.sender_private_key, to_be_signed)


# ---------------------------------------------------------------------------
# transport-independent messages (MO-15 §4.2.2)
# ---------------------------------------------------------------------------

def parse_transport_independent(raw: bytes):
    """Decode `bstr(Code | options | 0xff | payload)` (MO-15 §4.2.2)."""
    if not raw:
        raise VerifyError("empty transport-independent message")
    code = raw[0]
    rest = raw[1:]
    payload = b""
    if b"\xff" in rest:
        index = rest.index(b"\xff")
        options_raw, payload = rest[:index], rest[index + 1:]
    else:
        options_raw = rest
    return code, parse_options(options_raw), payload


def serialize_transport_independent(code: int, options, payload: bytes) -> bytes:
    """The encoding of MO-15 §4.2.2: Code byte, the option sequence, and the Payload
    Marker (0xff) plus payload when the payload is non-empty."""
    out = bytearray([code])
    out += serialize_options(options)
    if payload:
        out.append(0xFF)
        out += payload
    return bytes(out)


def decode_outer_message(msg: CoapMessage) -> InnerMessage:
    """Decode the transport-independent plaintext of an OSCORE message (RFC 8613 §5.3,
    Figure 9): Code | options | 0xff | payload, without the header, token or MID."""
    return InnerMessage(*parse_transport_independent(
        serialize_coap(msg, with_type_code_mid=False)))


# ---------------------------------------------------------------------------
# capture reading
# ---------------------------------------------------------------------------

def read_pcap(path: str):
    """Yield UDP payloads from a pcap/pcapng file without any external tool."""
    with open(path, "rb") as handle:
        data = handle.read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):  # little-endian, us / ns
        endian, div = "<", (1 if magic == b"\xd4\xc3\xb2\xa1" else 1000)
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):  # big-endian
        endian, div = ">", (1 if magic == b"\xa1\xb2\xc3\xd4" else 1000)
    elif magic == b"\x0a\x0d\x0d\x0a":
        return list(_read_pcapng(data))
    else:
        raise VerifyError("unrecognised capture file magic %s" % magic.hex())

    offset, out, index = 24, [], 0
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        packet = data[offset:offset + incl]
        offset += incl
        index += 1
        for payload, meta in _iter_udp(packet, linktype):
            out.append({"frame": index, "time": ts_sec + ts_frac / 1e6 / div, **meta,
                        "payload": payload.hex()})
    return out


def _read_pcapng(data: bytes):
    """Minimal pcapng reader: Enhanced Packet Blocks and Interface Description Blocks."""
    offset, endian, linktypes, out, index = 0, "<", [], 0
    while offset + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[offset:offset + 4])[0]
        if btype == 0x0A0D0D0A:  # a new section: figure out the byte order
            bom = struct.unpack("<I", data[offset + 8:offset + 12])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            btype = struct.unpack(endian + "I", data[offset:offset + 4])[0]
        blen = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]
        if blen < 12:
            break
        body = data[offset + 8:offset + blen - 4]
        if btype == 1 and len(body) >= 8:  # Interface Description Block
            linktypes.append(struct.unpack(endian + "H", body[0:2])[0])
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, incl, orig = struct.unpack(endian + "IIIII", body[0:20])
            packet = body[20:20 + incl]
            index += 1
            linktype = linktypes[iface] if iface < len(linktypes) else 1
            for payload, meta in _iter_udp(packet, linktype):
                out.append({"frame": index, "time": (ts_hi << 32 | ts_lo) / 1e6, **meta,
                            "payload": payload.hex()})
        offset += blen


# LINKTYPE values this reader understands.
LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LOOP = 0, 1, 101, 108
# AF_INET / AF_INET6 as written by BSD loopback captures, in either byte order.
AF_INET6_VALUES = {10, 23, 24, 28, 30}


def _iter_udp(packet: bytes, linktype: int = LINKTYPE_ETHERNET):
    """Yield (udp_payload, metadata) for each IPv4/IPv6 UDP datagram in a captured frame.

    Ethernet, BSD loopback (LINKTYPE_NULL / LINKTYPE_LOOP) and raw IP (LINKTYPE_RAW) are
    handled, so a capture taken on lo0 — which is where this profile runs — needs no
    external tool to be read back.
    """
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if len(packet) < 4:
            return
        family = struct.unpack_from("<I", packet, 0)[0]
        family_be = struct.unpack_from(">I", packet, 0)[0]
        for fam in (family, family_be):
            if fam == 2:
                yield from _iter_ipv4(packet, 4)
                return
            if fam in AF_INET6_VALUES:
                yield from _iter_ipv6(packet, 4)
                return
        return
    if linktype == LINKTYPE_RAW:
        version = packet[0] >> 4 if packet else 0
        if version == 4:
            yield from _iter_ipv4(packet, 0)
        elif version == 6:
            yield from _iter_ipv6(packet, 0)
        return
    if linktype != LINKTYPE_ETHERNET:
        raise VerifyError("unsupported link type %d" % linktype)
    if len(packet) < 14:
        return
    etype = struct.unpack_from(">H", packet, 12)[0]
    offset = 14
    # Skip 802.1Q tags.
    while etype in (0x8100, 0x88A8) and len(packet) >= offset + 4:
        etype = struct.unpack_from(">H", packet, offset + 2)[0]
        offset += 4
    if etype == 0x0800:  # IPv4
        yield from _iter_ipv4(packet, offset)
    elif etype == 0x86DD:  # IPv6
        yield from _iter_ipv6(packet, offset)


def _iter_ipv4(packet: bytes, offset: int):
    if len(packet) < offset + 20:
        return
    ihl = (packet[offset] & 0x0F) * 4
    proto = packet[offset + 9]
    src = ".".join(str(b) for b in packet[offset + 12:offset + 16])
    dst = ".".join(str(b) for b in packet[offset + 16:offset + 20])
    total = struct.unpack_from(">H", packet, offset + 2)[0]
    frag = struct.unpack_from(">H", packet, offset + 6)[0]
    l4 = offset + ihl
    end = min(len(packet), offset + total) if total else len(packet)
    if proto != 17 or (frag & 0x1FFF):
        return
    if l4 + 8 > end:
        return
    sport, dport, length = struct.unpack_from(">HHH", packet, l4)
    if length < 8:
        length = end - l4
    body = packet[l4 + 8:l4 + length]
    yield body, {"src": src, "sport": sport, "dst": dst, "dport": dport}


def _iter_ipv6(packet: bytes, offset: int):
    if len(packet) < offset + 40:
        return
    src = socket_inet_ntop(packet[offset + 8:offset + 24])
    dst = socket_inet_ntop(packet[offset + 24:offset + 40])
    next_header = packet[offset + 6]
    l4 = offset + 40
    hops = 0
    while next_header in (0, 43, 60) and hops < 8:  # hop-by-hop, routing, dest opts
        if l4 + 8 > len(packet):
            return
        next_header = packet[l4]
        l4 += 8 + packet[l4 + 1] * 8
        hops += 1
    if next_header != 17 or l4 + 8 > len(packet):
        return
    sport, dport, length = struct.unpack_from(">HHH", packet, l4)
    if length < 8:
        length = len(packet) - l4
    yield packet[l4 + 8:l4 + length], {"src": src, "sport": sport, "dst": dst,
                                      "dport": dport}




def socket_inet_ntop(raw: bytes) -> str:
    """Format 4 or 16 address octets; ::ffff:a.b.c.d renders as the IPv4 address."""
    if len(raw) == 16 and raw[:10] == b"\x00" * 10 + b"\xff\xff":
        return ".".join(str(b) for b in raw[12:16])
    return ipaddress.ip_address(raw).compressed


def load_trace(path: str):
    """Load a JSON trace (see `--emit-trace`) or a capture file."""
    if path.endswith(".json"):
        with open(path) as handle:
            return json.load(handle)
    return read_pcap(path)


# ---------------------------------------------------------------------------
# conformance matrix
# ---------------------------------------------------------------------------

ROW_TEXT = {
    "R9.9.0.1": "MO-15 §9: server and clients are members of the same OSCORE group.",
    "R9.9.0.2": "MO-15 §9: original registrations and unicast responses MUST also be protected.",
    "R9.9.0.3": "MO-15 §9: OSCORE (pairwise) on the unicast leg.",
    "R9.9.1.1": "MO-15 §9.1: join_uri (5) and sec_gp (6) absent (OPTIONAL, deferred).",
    "R9.9.1.2": "MO-15 §9.1: no other §9.1 group parameters present.",
    "R9.9.1.3": "MO-15 §9.1: no partial group configuration accepted.",
    "R9.9.1.4": "MO-15 §9.1: no §9.1 signalling mixed with the preconfigured profile.",
    "R9.9.2.1.1": "MO-15 §9.2.1: phantom request MUST use Group OSCORE group mode.",
    "R9.9.2.1.2": "MO-15 §9.2.1: ph_req PIV is the consumed SN; the next message differs.",
    "R9.9.2.1.3": "MO-15 §9.2.1 / GO-28 §3.2: kid, PIV and kid context match the fixture.",
    "R9.9.2.2.1": "MO-15 §9.2.2: ph_req encodes a Group OSCORE protected request.",
    "R9.9.2.2.2": "MO-15 §9.2.2: Code FETCH, outer options only, payload = ct + signature.",
    "R9.9.2.2.3": "MO-15 §9.2.2: every informative response carries ph_req.",
    "R9.9.2.2.4": "MO-15 §9.2.2: last_notif encodes the latest protected notification.",
    "R9.9.2.2.5": "MO-15 §9.2.2: no optional §9.1 parameters by default.",
    "R9.9.2.3.1": "MO-15 §9.2.3: every multicast notification is Group OSCORE group mode.",
    "R9.9.2.3.2": "MO-15 §9.2.3 / GO-28 §3.4: request_kid is the phantom kid.",
    "R9.9.2.3.3": "MO-15 §9.2.3: request_piv is the phantom PIV.",
    "R9.9.2.3.4": "MO-15 §9.2.3: request_kid_context is the phantom Gid.",
    "R9.9.2.3.5": "GO-28 §7.3: each response after the first carries its own PIV.",
    "R9.9.2.4.1": "MO-15 §9.2.4: protected cancellation is OPTIONAL for this version.",
    "R9.9.2.4.2": "MO-15 §9.2.4: cancellation PIV is OPTIONAL for this version.",
    "R9.9.3.1.1": "MO-15 §9.3.1: the client expects the ph_req parameter.",
    "R9.9.3.1.2": "MO-15 §9.3.1: decrypt and verify the rebuilt phantom request.",
    "R9.9.3.1.3": "MO-15 §9.3.1: no replay check on the phantom request.",
    "R9.9.3.1.4": "MO-15 §9.3.1: Replay Window MUST NOT be updated.",
    "R9.9.3.1.5": "MO-15 §9.3.1: MUST NOT deliver to the application.",
    "R9.9.3.1.6": "MO-15 §9.3.1: store phantom kid, PIV and kid context.",
    "R9.9.3.1.7": "MO-15 §9.3.1: failed verification — retry or withdraw.",
    "R9.9.3.1.8": "MO-15 §9.3.1: §5.2 Step 3 on the decrypted phantom request.",
    "R9.9.3.1.9": "MO-15 §9.3.1: decrypt and verify last_notif when present.",
    "R9.9.3.2.1": "MO-15 §9.3.2: decrypt and verify every multicast notification.",
    "R9.9.3.2.2": "MO-15 §9.3.2: AAD takes the phantom request_kid / piv / kid context.",
    "R9.G3.4.1": "GO-28 §3.4: external_aad is a bstr-wrapped nine-element CBOR array.",
    "R9.G3.4.2": "GO-28 §3.4: the four algorithms, null where unset.",
    "R9.G3.4.3": "GO-28 §3.4: OSCORE_option is the finalized option value.",
    "R9.G3.4.4": "GO-28 §3.4: sender_cred and gm_cred are CBOR byte strings.",
    "R9.G7.1.1": "GO-28 §7.1: Group Flag 1, Group Encryption Algorithm, countersignature.",
    "R9.G7.2.1": "GO-28 §7.2: failed signature stops processing.",
    "R9.G7.2.2": "GO-28 §7.2: own-kid request is the multicast Observe exception.",
    "R9.G7.3.1": "GO-28 §7.3: long-exchange responses use the stored request tuple.",
    "R9.G7.4.1": "GO-28 §7.4: bad signature/ciphertext stops processing.",
    "R9.G7.4.2": "GO-28 §7.4: stored kid and kid context used; ordering enforced.",
    "R9.10.1": "MO-15 §10: the deterministic identifiers and tokens.",
    "R9.10.2": "MO-15 §10: pairwise unicast leg, Group OSCORE group leg.",
    "R9.10.3": "MO-15 §10: request_kid 05, request_piv 01f5, request_kid_context 57ab2e.",
    "R9.10.4": "MO-15 §10: phantom 501, INIT_NOTIF 502, first wire notification 503.",
}

# Rows whose check needs an internal assertion rather than wire evidence; the matrix
# records a dash for those.  They are reported as NOT-WIRE-CHECKED, never as PASS.
# Rows whose remaining part is endpoint state that only an implementation can show: the
# cryptographic and wire part is checked elsewhere in the analysis, and the state part —
# replay-window bookkeeping, application delivery, the Response Number — is left to the
# implementation's own protocol-unit tests.
INTERNAL_ONLY = {
    "R9.9.3.1.4",  # the Replay Window must stay byte-for-byte unchanged
}

# Rows that are OPTIONAL and deferred for this profile.  The first group is decidable from
# the wire — the profile must simply not emit them — so it is checked and passes on
# absence.  The second group is the behaviour of a mechanism this version does not
# implement, so it can only be recorded as out of scope.
DEFERRED = {"R9.9.1.1", "R9.9.1.2", "R9.9.2.2.5"}
DEFERRED_OUT_OF_SCOPE = {"R9.9.1.3", "R9.9.1.4", "R9.9.2.4.1", "R9.9.2.4.2"}

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


class Conformance:
    """Accumulates per-row outcomes and renders the table."""

    def __init__(self):
        self.rows = {}
        self.order = []

    def record(self, row, status, detail=""):
        if row not in self.rows:
            self.order.append(row)
        self.rows[row] = (status, detail)

    def skip(self, row, reason):
        self.record(row, SKIP, reason)

    def note(self, row, ok, detail=""):
        """Record a wire check, but keep a stronger earlier failure."""
        if row in self.rows and self.rows[row][0] == FAIL:
            if detail not in self.rows[row][1]:
                self.rows[row] = (FAIL, self.rows[row][1] + "; " + detail)
            return ok
        self.record(row, PASS if ok else FAIL, detail)
        return ok

    @property
    def failed(self):
        return [r for r in self.order if self.rows[r][0] == FAIL]

    def render(self, stream=sys.stdout):
        width = max([len(r) for r in self.order] + [4])
        for row in self.order:
            status, detail = self.rows[row]
            stream.write("%-6s %-*s  %s\n" % (status, width, row, ROW_TEXT.get(row, "")))
            if detail:
                for line in detail.splitlines():
                    stream.write("       %s\n" % line)
        stream.write("\n%d rows: %d PASS, %d FAIL, %d NOT-CHECKABLE-ON-WIRE\n"
                     % (len(self.order),
                        sum(1 for r in self.order if self.rows[r][0] == PASS),
                        len(self.failed),
                        sum(1 for r in self.order if self.rows[r][0] == SKIP)))


# ---------------------------------------------------------------------------
# authentication credentials (COSE_Key)
# ---------------------------------------------------------------------------

COSE_KTY = 1
COSE_KID = 2
COSE_ALG = 3
COSE_KEY_X_EC2 = -25   # RFC 9052 §7.1: EC2 x coordinate
COSE_KEY_X_EDDSA = -2  # draft-ietf-cose-eddsa / RFC 9052 §7.2: EdDSA x (the public key)
COSE_KEY_Y_EC2 = -26
COSE_KEY_D = -3       # draft-ietf-cose-eddsa: the private key seed
COSE_KEY_CRV = -1
COSE_KTY_OKP = 1
COSE_CRV_ED25519 = 6
CRED_CONTAINER = 8  # draft-ietf-core-oscore-credential-format: Credential label 8
CRED_COSE_KEY = 1  # the Container's label 1 is the COSE_Key


def parse_credential(cred: bytes):
    """The COSE_Key inside an authentication credential.

    The credentials of this profile follow draft-ietf-core-oscore-credential-format:
    a map whose label 8 holds a Container, whose label 1 is the COSE_Key.  A bare COSE_Key
    is accepted as well, so the verifier works on either encoding.
    """
    value, offset = cbor_decode(cred, 0)
    if offset != len(cred):
        raise VerifyError("trailing bytes after the credential")
    if not isinstance(value, dict):
        raise VerifyError("credential is not a CBOR map")
    container = value.get(CRED_CONTAINER)
    if isinstance(container, dict):
        if CRED_COSE_KEY not in container:
            raise VerifyError("credential Container has no COSE_Key at label 1")
        value = container[CRED_COSE_KEY]
        if not isinstance(value, dict):
            raise VerifyError("the credential's COSE_Key is not a CBOR map")
    return value


def credential_public_key(cred: bytes, alg):
    """The verification key of an authentication credential (GO-28 §7.2 Step 6 uses "the
    public key from the ... authentication credential")."""
    key = parse_credential(cred)
    if not isinstance(key.get(COSE_KTY), int):
        raise VerifyError("COSE_Key has no 'kty'")
    x = credential_x(key)
    if COSE_KEY_Y_EC2 in key and len(key[COSE_KEY_Y_EC2]) != 0:
        raise VerifyError("only the Ed25519 (EdDSA) key form is supported here")
    return public_key_from_credential_x(alg, x)


def credential_x(cred) -> bytes:
    """The public-key coordinate of a COSE_Key.

    An EdDSA (Ed25519) COSE_Key carries it at label -2; an EC2 COSE_Key at label -25.
    Both spellings are accepted so the verifier does not depend on the credential format
    chosen by the implementation under test.
    """
    key = parse_credential(cred) if isinstance(cred, (bytes, bytearray)) else cred
    for label in (COSE_KEY_X_EDDSA, COSE_KEY_X_EC2):
        if label in key:
            return key[label]
    raise VerifyError("COSE_Key carries neither label -2 (EdDSA x) nor label -25 (EC2 x)")


# ---------------------------------------------------------------------------
# the Section-10-derived test vector
# ---------------------------------------------------------------------------

def _h(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise VerifyError("expected a hex string, got %r" % (value,))
    text = value.strip().replace(" ", "").replace(":", "")
    if len(text) % 2:
        raise VerifyError("odd-length hex string %r" % value)
    return bytes.fromhex(text)


def _int(value) -> int:
    return int(value)


class ClientSide:
    """Everything one client needs, as declared by the test vector."""

    def __init__(self, spec, group_common):
        self.label = spec["label"]
        self.token = _h(spec["token"])
        pair = spec["pairwise"]
        self.pairwise = PairwiseContext(
            _h(pair["master_secret"]), _h(group_common["master_salt"]),
            aead_alg=_int(group_common["aead_alg"]), hkdf_alg=_int(group_common["hkdf_alg"]),
            sender_id=_h(pair["sender_id"]), recipient_id=_h(pair["recipient_id"]),
            id_context=_h(pair["id_context"]) if pair.get("id_context") else None,
            label=self.label)
        self.start_sn = _int(pair["start_sn"])
        self.pairwise_server_key = _h(pair["server_public_key"]) if pair.get(
            "server_public_key") else None
        group = dict(group_common)
        # `sender_cred` in the external_aad (GO-28 §3.4) is the credential of the endpoint
        # that protected the message being verified — here, the server, for the phantom
        # request and every multicast notification.  It is not this client's own credential.
        self.own_cred = _h(spec["group_sender"]["cred"])
        self.group = GroupContext(
            _h(group["master_secret"]), _h(group["master_salt"]), _h(group["gid"]),
            aead_alg=_int(group["aead_alg"]), hkdf_alg=_int(group["hkdf_alg"]),
            group_enc_alg=_int(group["alg_group_enc"]),
            signature_alg=_int(group["alg_signature"]),
            pairwise_key_agreement_alg=(
                _int(group["alg_pairwise_key_agreement"])
                if group.get("alg_pairwise_key_agreement") is not None else None),
            sender_cred=_h(group["sender_cred"]), gm_cred=_h(group["gm_cred"]),
            sender_id=_h(spec["group_sender"]["id"]),
            recipient_id=_h(spec["group_sender"]["peer_id"]),
            sender_private_key=private_key_from_seed(
                _int(group["alg_signature"]), _h(spec["group_sender"]["private_key_seed"])),
            recipient_pubkey=credential_public_key(
                _h(group["recipients"][0]["cred"]), _int(group["alg_signature"])),
            label=self.label)


class Vector:
    """The "Section-10-derived test vector": every chosen input of the scenario.

    Every value in it is a public test fixture taken from the shipped profiles
    (`docs/secure/examples/section10/*.conf`); the draft defines no ciphertext.
    """

    def __init__(self, doc):
        self.doc = doc
        self.title = doc.get("title", "Section-10-derived test vector")
        group = dict(doc["group"])
        self.group = GroupContext(
            _h(group["master_secret"]), _h(group["master_salt"]), _h(group["gid"]),
            aead_alg=_int(group["aead_alg"]), hkdf_alg=_int(group["hkdf_alg"]),
            group_enc_alg=_int(group["alg_group_enc"]),
            signature_alg=_int(group["alg_signature"]),
            pairwise_key_agreement_alg=(
                _int(group["alg_pairwise_key_agreement"])
                if group.get("alg_pairwise_key_agreement") is not None else None),
            sender_cred=_h(group["sender_cred"]), gm_cred=_h(group["gm_cred"]),
            sender_id=_h(group["sender"]["id"]), recipient_id=b"",
            sender_private_key=private_key_from_seed(
                _int(group["alg_signature"]), _h(group["sender"]["private_key_seed"])),
            label="server")
        self.clients = [ClientSide(spec, group) for spec in doc["clients"]]
        self.by_token = {c.token: c for c in self.clients}
        scenario = doc.get("scenario", doc)
        self.resource = scenario.get("resource", "r")
        self.values = [v if isinstance(v, bytes) else v.encode()
                       for v in scenario.get("representation_values", [])]
        # MO-15 §4.1 Step 6: INIT_NOTIF carries "the current representation of the target
        # resource as its payload" and is stored, not transmitted.  The draft fixes no
        # value, so a profile starts its counter where it likes and publishes the baseline
        # here; `values` above remains the list of what the profile *transmits*.
        self.initial_value = [v if isinstance(v, bytes) else v.encode()
                              for v in scenario.get("initial_value", [])]
        self.phantom_token = _h(scenario["phantom_token"])
        self.group_addr = scenario.get("group_address", "")
        self.group_port = _int(scenario.get("group_port", 61616))
        self.server_port = _int(scenario.get("server_port", 5683))
        self.expected = doc.get("expected", {})
        # The server's view of a client's pairwise context: same Master Secret, the IDs
        # swapped.  Used to recompute the informative responses from the declared inputs.
        self.server_pairwise = {}
        for spec in doc["clients"]:
            pair = spec["pairwise"]
            self.server_pairwise[_h(pair["sender_id"])] = PairwiseContext(
                _h(pair["master_secret"]), _h(group["master_salt"]),
                aead_alg=_int(group["aead_alg"]), hkdf_alg=_int(group["hkdf_alg"]),
                sender_id=_h(pair["recipient_id"]), recipient_id=_h(pair["sender_id"]),
                id_context=_h(pair["id_context"]) if pair.get("id_context") else None,
                label="server<-%s" % spec["label"])
        # The clients' view of the server in the group context, for the phantom request.
        self.client_group = {}
        for spec in doc["clients"]:
            g = dict(group)
            self.client_group[spec["label"]] = GroupContext(
                _h(g["master_secret"]), _h(g["master_salt"]), _h(g["gid"]),
                aead_alg=_int(g["aead_alg"]), hkdf_alg=_int(g["hkdf_alg"]),
                group_enc_alg=_int(g["alg_group_enc"]),
                signature_alg=_int(g["alg_signature"]),
                pairwise_key_agreement_alg=(
                    _int(g["alg_pairwise_key_agreement"])
                    if g.get("alg_pairwise_key_agreement") is not None else None),
                sender_cred=_h(g["sender_cred"]), gm_cred=_h(g["gm_cred"]),
                sender_id=_h(spec["group_sender"]["id"]),
                recipient_id=_h(spec["group_sender"]["peer_id"]),
                sender_private_key=private_key_from_seed(
                    _int(g["alg_signature"]), _h(spec["group_sender"]["private_key_seed"])),
                recipient_pubkey=credential_public_key(
                    _h(g["recipients"][0]["cred"]), _int(g["alg_signature"])),
                label=spec["label"])

    def client_for_kid(self, kid: bytes):
        for client in self.clients:
            if client.pairwise.sender_id == kid:
                return client
        return None


def load_vector(path: str) -> Vector:
    with open(path) as handle:
        return Vector(json.load(handle))


# ---------------------------------------------------------------------------
# scenario analysis
# ---------------------------------------------------------------------------

def rebuild_transport_independent(raw: bytes, mtype: int, mid: int, token: bytes,
                                  default_options=None) -> CoapMessage:
    """Rebuild the CoAP message that `bstr(Code | options | 0xff | payload)` (MO-15 §4.2.2)
    stands for.

    The encoding carries no Message ID, no Type and no Token: MO-15 §4.2.2 defines it as
    transport-independent information.  The reconstruction therefore supplies the values
    the draft fixes elsewhere — the phantom request is a Non-confirmable FETCH with the
    allocated Token (§4.1 / Figure 7), a multicast notification is Non-confirmable
    (§4.3) with the phantom Token and MID 0 — and is only used to feed the cryptographic
    checks, which cover the ciphertext and not the outer header.
    """
    code, options, payload = parse_transport_independent(raw)
    if default_options is None:
        default_options = []
    return CoapMessage(mtype, code, mid, token, list(options) + list(default_options),
                       payload)


def flip(payload: bytes, index: int) -> bytes:
    """One-byte tamper, used for the authenticity negative tests."""
    out = bytearray(payload)
    out[index] ^= 0x01
    return bytes(out)


def decode_tp_info(value):
    """Decode the 'tp_info' array of the informative response (MO-15 §4.2.1.1, Figure 3).

    Returns a dict with 'server', 'client' (each a CRI of scheme-id and authority) and
    'token'.  The CRI form used here is [scheme-id, authority] with the authority as
    [host, port?] (agreed with the draft authors).
    """
    if not isinstance(value, list) or len(value) != 3:
        raise VerifyError("'tp_info' is not a three-element array")
    out = {}
    for index, name in ((0, "server"), (1, "client")):
        cri = value[index]
        if not isinstance(cri, list) or len(cri) != 2:
            raise VerifyError("'tpi_%s' is not a [scheme-id, authority] CRI" % name)
        out[name] = {"scheme_id": cri[0], "authority": cri[1]}
    if not isinstance(value[2], (bytes, bytearray)):
        raise VerifyError("'tpi_token' is not a CBOR byte string")
    out["token"] = bytes(value[2])
    return out


class Registration:
    """One client's protected observation registration and its informative response."""

    def __init__(self, client, request_msg, request_osc, frame):
        self.client = client
        self.request = request_msg
        self.osc = request_osc
        self.frame = frame
        self.request_kid = request_osc.kid or b""
        self.request_piv = request_osc.piv
        self.inner_request = None
        self.response = None
        self.response_frame = None
        self.inner_response = None
        self.ir = None
        self.tp_info = None
        self.phantom = None      # CoapMessage
        self.phantom_osc = None
        self.phantom_result = None
        self.last_notif = None
        self.last_notif_osc = None
        self.last_notif_result = None
        self.token = request_msg.token


class Analysis:
    def __init__(self, vector: Vector, packets, verbose=False):
        self.vector = vector
        self.packets = packets
        self.verbose = verbose
        self.conf = Conformance()
        self.registrations = []
        self.notifications = []   # (packet index, CoapMessage, osc)
        self.notes = []
        self.shared_last_notif = False
        self.signature_forms = set()
        self.gid = vector.group.gid

    # -- helpers ---------------------------------------------------------
    def log(self, text):
        if self.verbose:
            print("    " + text)

    def client_context(self, label):
        return self.vector.client_group[label]

    # -- main ------------------------------------------------------------
    def run(self) -> Conformance:
        self.collect()
        self.check_registrations()
        self.check_informative_responses()
        self.check_phantom()
        self.check_last_notif()
        self.check_notifications()
        self.check_aad_structure()
        self.check_option_bound_aad()
        self.check_tamper()
        self.check_expected()
        self.finalise()
        return self.conf

    def finalise(self):
        """Record every row of the matrix.

        A row the capture cannot decide is reported as NOT-CHECKABLE-ON-WIRE with the
        reason, never as a pass: docs/secure/conformance.md records a dash under "Wire
        evidence" for those and they are proved by an internal assertion or a
        protocol-unit test instead.
        """
        for row in sorted(ROW_TEXT):
            if row in self.conf.rows:
                continue
            if row in DEFERRED:
                self.conf.skip(row, "OPTIONAL and deferred; decided above by checking that "
                                   "the profile does not emit it")
            elif row in DEFERRED_OUT_OF_SCOPE:
                self.conf.skip(row, "OPTIONAL for this version and not implemented "
                                   "(docs/secure/plan.md, fixed scope), so there is nothing "
                                   "on the wire to check")
            elif row in INTERNAL_ONLY:
                self.conf.skip(row, "internal assertion: the crypto and the decoded fields "
                                   "are proved above, and what is left is endpoint state "
                                   "that a capture cannot show (docs/secure/conformance.md "
                                   "records a dash under \"Wire evidence\" for this row)")
            else:
                self.conf.skip(row, "not decidable from a capture "
                                   "(docs/secure/conformance.md records a dash under "
                                   "\"Wire evidence\" for this row)")

    def collect(self):
        """Parse the capture and pair each request with its informative response."""
        self.messages = []
        for packet in self.packets:
            raw = bytes.fromhex(packet["payload"])
            try:
                msg = parse_coap(raw)
            except VerifyError as error:
                self.notes.append("frame %s: not CoAP (%s)" % (packet.get("frame"), error))
                continue
            if msg.code == 0 and msg.mtype in (2, 3):  # empty ACK / RST
                self.messages.append((packet, msg, None))
                continue
            option = msg.oscore_option()
            osc = parse_oscore_option(option) if option is not None else None
            self.messages.append((packet, msg, osc))
            if osc is not None and osc.group and packet.get("dport") == self.vector.group_port:
                self.notifications.append((packet, msg, osc))

        for packet, msg, osc in self.messages:
            if not (msg.is_request and osc is not None and not osc.group):
                continue
            client = self.vector.client_for_kid(osc.kid or b"")
            if client is None:
                self.notes.append("frame %s: request kid %s matches no configured client"
                                  % (packet.get("frame"), (osc.kid or b"").hex()))
                continue
            self.registrations.append(Registration(client, msg, osc, packet.get("frame")))

        # Attach the informative response that answers each registration.  The response is
        # identified by the outer Token, which RFC 8613 §4.1.3.2 keeps in the clear.
        for packet, msg, osc in self.messages:
            if msg.is_request or osc is None:
                continue
            for reg in self.registrations:
                if msg.token == reg.token:
                    reg.response, reg.response_frame = msg, packet.get("frame")
                    break

    # -- unicast leg -----------------------------------------------------
    def check_registrations(self):
        conf = self.conf
        if not self.registrations:
            conf.record("R9.9.0.2", FAIL, "no OSCORE-protected registration request found")
            return
        details, ok_leg, ok_group_flag = [], True, True
        for reg in self.registrations:
            result = verify_pairwise(reg.request, reg.client.pairwise,
                                     key=reg.client.pairwise.sender_key)
            reg.inner_request = result.plaintext if result.ok else None
            if not result.ok:
                ok_leg = False
                details.append("frame %s: %s" % (reg.frame, result.note))
                continue
            inner = result.plaintext
            self.log("frame %s %s: outer FETCH kid=%s piv=%s -> inner %s"
                     % (reg.frame, reg.client.label, reg.request_kid.hex(),
                        reg.request_piv.hex(), inner))
            if reg.osc.group:
                ok_group_flag = False
            # R9.10.1: MO-15 §10 fixes the Sender IDs, the starting SNs and the Tokens.
            expected_token = reg.client.token
            if reg.token != expected_token:
                ok_leg = False
                details.append("frame %s: Token %s, §10 requires %s for %s"
                               % (reg.frame, reg.token.hex(), expected_token.hex(),
                                  reg.client.label))
            if inner.code != CODE_GET:
                ok_leg = False
                details.append("frame %s: inner Code %02x, §10/Figure 7 requires GET (01)"
                               % (reg.frame, inner.code))
            observe = inner.opt(OPT_OBSERVE)
            if observe is None or parse_uint(observe) != 0:
                ok_leg = False
                details.append("frame %s: inner Observe %r, Figure 7 requires 0 (register)"
                               % (reg.frame, observe))
            if inner.opts(OPT_URI_PATH) != [self.vector.resource.encode()]:
                ok_leg = False
                details.append("frame %s: inner Uri-Path %r, Figure 7 requires %r"
                               % (reg.frame, inner.opts(OPT_URI_PATH),
                                  self.vector.resource))
            # R9.9.2.1.2 / R9.10.1: the request Partial IV is the consumed Sender SN.
            if int.from_bytes(reg.request_piv, "big") != reg.client.start_sn:
                ok_leg = False
                details.append("frame %s: request PIV %d, the §10 starting SN is %d"
                               % (reg.frame, int.from_bytes(reg.request_piv, "big"),
                                  reg.client.start_sn))
        conf.note("R9.9.0.2", ok_leg,
                  "every registration carries OSCORE and decrypts to the inner GET/\n"
                  "Observe shown in MO-15 §10 Figure 7; the informative responses are\n"
                  "checked separately below." + ("".join("\n" + d for d in details)))
        conf.note("R9.9.0.3", ok_leg and ok_group_flag,
                  "the unicast leg is protected with plain RFC 8613 OSCORE:\n"
                  "no Group Flag on any registration or informative response.")
        conf.note("R9.10.1", ok_leg,
                  "Sender IDs 01/02 with starting SNs 101/201 and Tokens %s/%s, resource %r"
                  % (self.vector.clients[0].token.hex(), self.vector.clients[-1].token.hex(),
                     self.vector.resource))

    def shared_parameter(self, key):
        """True when every informative response of the group observation carries the same
        value for the given parameter — MO-15 §9.2.2 returns the *same* protected phantom
        request and the same stored latest notification to every observer."""
        with_parameter = [r for r in self.registrations if r.ir and key in r.ir]
        if not with_parameter or len(with_parameter) != len(self.registrations):
            return False
        return len({r.ir[key] for r in with_parameter}) == 1

    def check_informative_responses(self):
        conf = self.conf
        details, ok_crypto, ok_keys, ok_no_join = [], True, True, True
        present_keys = None
        for reg in self.registrations:
            if reg.response is None:
                ok_crypto = False
                details.append("%s: no informative response in the capture"
                               % reg.client.label)
                continue
            result = verify_pairwise(reg.response, reg.client.pairwise,
                                     request_kid=reg.request_kid,
                                     request_piv=reg.request_piv)
            if not result.ok:
                ok_crypto = False
                details.append("frame %s (%s): %s" % (reg.response_frame, reg.client.label,
                                                      result.note))
                continue
            inner = result.plaintext
            reg.inner_response = inner
            self.log("frame %s %s: outer 2.04 -> inner %s"
                     % (reg.response_frame, reg.client.label, inner))
            # MO-15 §10 Figure 7 shows the outer 2.04 with an inner 5.03; the inner code
            # 5.03 with Content-Format application/informative-response+cbor.
            if inner.code != CODE_SERVICE_UNAVAILABLE:
                ok_crypto = False
                details.append("frame %s: inner Code %02x, Figure 7 requires 5.03"
                               % (reg.response_frame, inner.code))
            if reg.response.code != CODE_CHANGED:
                ok_crypto = False
                details.append("frame %s: outer Code %02x, the informative response uses "
                               "2.04 (RFC 8613 §4.2)"
                               % (reg.response_frame, reg.response.code))
            cf = inner.opt(OPT_CONTENT_FORMAT)
            if cf is None or parse_uint(cf) != CF_INFORMATIVE_RESPONSE:
                ok_crypto = False
                details.append("frame %s: inner Content-Format %r, the test value is %d"
                               % (reg.response_frame, cf, CF_INFORMATIVE_RESPONSE))
            try:
                ir, end = cbor_decode(inner.payload, 0)
            except CborError as error:
                ok_crypto = False
                details.append("frame %s: informative-response payload is not CBOR (%s)"
                               % (reg.response_frame, error))
                continue
            if end != len(inner.payload) or not isinstance(ir, dict):
                ok_crypto = False
                details.append("frame %s: informative-response payload is not a CBOR map"
                               % reg.response_frame)
                continue
            reg.ir = ir
            if 0 in ir:
                try:
                    reg.tp_info = decode_tp_info(ir[0])
                except VerifyError as error:
                    details.append("frame %s: 'tp_info' — %s" % (reg.response_frame, error))
            keys = sorted(ir)
            present_keys = keys if present_keys is None else present_keys
            # R9.9.3.1.1: the client expects 'ph_req'; without it the response is malformed.
            if 1 not in ir:
                ok_keys = False
                details.append("frame %s: informative response has no 'ph_req' (key 1)"
                               % reg.response_frame)
            for key in keys:
                if key in IR_JOIN_KEYS:
                    ok_no_join = False
                    details.append("frame %s: informative response carries %r (key %d); the "
                                   "§9.1 group-join signalling is deferred in this profile"
                                   % (reg.response_frame, IR_KEYS.get(key, "?"), key))
        # R9.9.2.2.3 / R9.10.2: every informative response of the group observation carries
        # the same 'ph_req'.
        same_ph_req = self.shared_parameter(1)
        self.shared_last_notif = self.shared_parameter(2)

        conf.note("R9.9.0.2", ok_crypto,
                  "each informative response is OSCORE-protected and decrypts to the inner\n"
                  "5.03 with Content-Format %d (MO-15 §10 Figure 7, outer 2.04 per\n"
                  "RFC 8613 §4.2)."
                  % CF_INFORMATIVE_RESPONSE + ("".join("\n" + d for d in details)))
        conf.note("R9.9.1.1", ok_no_join, "no 'join_uri' (5) or 'sec_gp' (6) in any "
                  "informative response.")
        conf.note("R9.9.1.2", ok_no_join, "no other §9.1 group parameter in any "
                  "informative response.")
        conf.note("R9.9.1.3", ok_no_join, "no partial group configuration was accepted: "
                  "no §9.1 field appears at all.")
        conf.note("R9.9.1.4", ok_no_join, "no §9.1 signalling is mixed with the "
          "preconfigured group profile.")
        conf.note("R9.9.2.2.3", same_ph_req and ok_keys,
                  "every informative response of the group observation carries 'ph_req', and "
                  "all of them carry the identical protected phantom request.")
        conf.note("R9.9.2.2.5", ok_no_join, "no optional §9.1 parameters by default.")
        conf.note("R9.9.3.1.1", ok_keys,
                  "'ph_req' is present in every informative response; a response without "
                  "key 1 would be malformed (MO-15 §9.3.1 Step 2).")
        conf.note("R9.10.2", ok_crypto and same_ph_req,
                  "pairwise OSCORE on the two unicast legs, one Group OSCORE group "
                  "observation shared through one 'ph_req'.")

    # -- phantom request and last_notif ----------------------------------
    def _rebuild_and_verify(self, reg, raw, mtype, is_request, label):
        """Rebuild a `ph_req` / `last_notif` value and verify it in the group context.

        The `request_kid` / `request_piv` / `request_kid_context` elements of the
        external_aad are the values of the *associated request*: for the phantom request
        that is the message's own OSCORE Option, for every notification it is the stored
        phantom request's (MO-15 §9.2.3, §9.3.2).
        """
        token = self.vector.phantom_token
        msg = rebuild_transport_independent(raw, mtype, 0, token)
        osc = parse_oscore_option(msg.oscore_option() or b"")
        ctx = self.client_context(reg.client.label)
        if is_request:
            request_kid, request_piv = osc.kid or b"", osc.piv
        elif reg.phantom_osc is not None:
            request_kid, request_piv = reg.phantom_osc.kid or b"", reg.phantom_osc.piv
        else:
            request_kid, request_piv = osc.kid or b"", osc.piv
        request_kid_context = (osc.kid_context if osc.kid_context is not None else self.gid)
        result = verify_group(msg, ctx, request_kid=request_kid, request_piv=request_piv,
                              request_kid_context=request_kid_context,
                              is_request=is_request)
        self.log("%s %s: %s -> %s (%s)" % (reg.client.label, label, osc, result.ok,
                                           result.note))
        if result.ok:
            self.signature_forms.add(result.signature_form)
        return msg, osc, result

    def check_phantom(self):
        conf = self.conf
        details, ok, ok_shape, ok_ids = [], True, True, True
        found = False
        for reg in self.registrations:
            if not reg.ir or 1 not in reg.ir:
                continue
            found = True
            raw = reg.ir[1]
            msg, osc, result = self._rebuild_and_verify(
                reg, raw, mtype=1, is_request=True, label="ph_req")
            reg.phantom, reg.phantom_osc, reg.phantom_result = msg, osc, result
            if not result.ok:
                ok = False
                details.append("%s: ph_req — %s" % (reg.client.label, result.note))
                continue
            # R9.9.2.2.2: the Code is FETCH, the options are the outer non-encrypted ones,
            # the payload is the ciphertext followed by the encrypted countersignature.
            if osc.piv != b"" and not osc.group:
                ok_shape = False
                details.append("%s: ph_req is not group mode" % reg.client.label)
            if msg.code != CODE_FETCH:
                ok_shape = False
                details.append("%s: ph_req Code %02x, MO-15 §9.2.2 requires FETCH (05)"
                               % (reg.client.label, msg.code))
            if msg.token != self.vector.phantom_token:
                ok_shape = False
                details.append("%s: ph_req Token %s, §10 allocates %s"
                               % (reg.client.label, msg.token.hex(),
                                  self.vector.phantom_token.hex()))
            payload = msg.payload
            if len(payload) <= signature_length(self.vector.group.signature_alg):
                ok_shape = False
                details.append("%s: ph_req carries no countersignature" % reg.client.label)
            # R9.9.2.1.3 / R9.10.3: kid, PIV and kid context of the phantom request.
            expected = self.vector.expected.get("phantom", {})
            if "kid" in expected and osc.kid != _h(expected["kid"]):
                ok_ids = False
                details.append("%s: ph_req kid %s, §10 requires %s"
                               % (reg.client.label, (osc.kid or b"").hex(), expected["kid"]))
            if "piv" in expected and osc.piv != _h(expected["piv"]):
                ok_ids = False
                details.append("%s: ph_req Partial IV %s, §10 requires %s (SN 501)"
                               % (reg.client.label, osc.piv.hex(), expected["piv"]))
            if "kid_context" in expected:
                want = _h(expected["kid_context"])
                if osc.kid_context is None:
                    ok_ids = False
                    details.append("%s: ph_req carries no kid context" % reg.client.label)
                elif osc.kid_context != want:
                    ok_ids = False
                    details.append("%s: ph_req kid context %s, §10 requires %s"
                                   % (reg.client.label, osc.kid_context.hex(), expected["kid_context"]))
            # R9.G7.2.2: the phantom request is protected with the server's own Sender ID,
            # the multicast Observe exception to "SHOULD NOT process an own-kid request".
            if osc.kid != _h(self.vector.group.sender_id):
                ok_ids = False
                details.append("%s: ph_req kid %s is not the server Sender ID %s"
                               % (reg.client.label, (osc.kid or b"").hex(),
                                  self.vector.group.sender_id.hex()))
            self.log("%s ph_req inner: %s" % (reg.client.label, result.plaintext))
        if not found:
            conf.record("R9.9.2.1.1", FAIL, "no 'ph_req' parameter in any informative "
                       "response")
            for row in ("R9.9.2.1.2", "R9.9.2.1.3", "R9.9.2.2.1", "R9.9.2.2.2",
                        "R9.9.3.1.2", "R9.G7.1.1", "R9.G7.2.2", "R9.10.3"):
                conf.record(row, FAIL, "no phantom request to check")
            return
        conf.note("R9.9.0.1", ok,
                  "the phantom request and every multicast notification verify under the "
                  "configured Gid (%s) and group credentials, i.e. the same OSCORE group, "
                  "and not under any pairwise context." % self.gid.hex())
        conf.note("R9.9.2.1.1", ok,
                  "the phantom request is protected with Group OSCORE in group mode and "
                  "independently verifies with the group Recipient Context.")
        conf.note("R9.9.2.2.1", ok_shape,
                  "'ph_req' is CBOR key 1 and its bytes are Code | options | 0xff |\n"
                  "ciphertext || encrypted countersignature (MO-15 §4.2.2, §9.2.2).")
        conf.note("R9.9.2.2.2", ok_shape,
                  "the phantom Code is FETCH (0.05), only outer options are present, and the "
                  "payload is the ciphertext followed by the countersignature.")
        conf.note("R9.9.3.1.2", ok,
                  "the rebuilt phantom registration request decrypts and its server "
                  "countersignature verifies (GO-28 §7.2).")
        conf.note("R9.G7.1.1", ok,
                  "Group Flag 1 on the phantom request, the Group Encryption Algorithm is "
                  "used for the AEAD, and the payload carries the encrypted countersignature.")
        conf.note("R9.9.2.1.3", ok_ids,
                  "the phantom OSCORE Option carries kid = %s (the server Sender ID), "
                  "Partial IV = %s and kid context = %s, matching the configured fixture "
                  "(GO-28 §3.2 supplies the Gid as the request kid context)."
                  % ((osc.kid or b"").hex(), osc.piv.hex(),
                     osc.kid_context.hex() if osc.kid_context else "-"))
        conf.note("R9.G7.2.2", ok_ids,
                  "the phantom request 'kid' equals the server's Sender ID (%s): the "
                  "multicast Observe exception to the own-kid rule."
                  % self.vector.group.sender_id.hex())
        conf.note("R9.10.3", ok_ids,
                  "request_kid = %s, request_piv = %s, request_kid_context = %s, exactly "
                  "the phantom OSCORE Option fields of MO-15 §10 Figure 7."
                  % (_h(self.vector.expected.get("phantom", {}).get("kid", "00")).hex(),
                     _h(self.vector.expected.get("phantom", {}).get("piv", "0")).hex(),
                     self.gid.hex()))

    def check_last_notif(self):
        conf = self.conf
        details, ok, ok_present = [], True, False
        for reg in self.registrations:
            if not reg.ir or 2 not in reg.ir:
                continue
            ok_present = True
            msg, osc, result = self._rebuild_and_verify(
                reg, reg.ir[2], mtype=1, is_request=False, label="last_notif")
            reg.last_notif, reg.last_notif_osc, reg.last_notif_result = msg, osc, result
            if not result.ok:
                ok = False
                details.append("%s: last_notif — %s" % (reg.client.label, result.note))
                continue
            if osc.kid != _h(self.vector.group.sender_id):
                ok = False
                details.append("%s: last_notif kid %s is not the server Sender ID"
                               % (reg.client.label, (osc.kid or b"").hex()))
            if osc.piv == reg.phantom_osc.piv:
                ok = False
                details.append("%s: last_notif reuses the phantom Partial IV %s; the server "
                               "Sender SN must have advanced"
                               % (reg.client.label, osc.piv.hex()))
            self.log("%s last_notif inner: %s" % (reg.client.label, result.plaintext))
        same_last_notif = self.shared_last_notif
        conf.note("R9.9.2.2.4", ok and ok_present and same_last_notif,
                  "'last_notif' decodes and verifies as a Group OSCORE protected multicast "
                  "notification, with its own fresh Partial IV"
                  + (", and both clients receive the identical stored bytes"
                     if same_last_notif else "")
                  + ".\n"
                  "One protection and one Sender Sequence Number are consumed per latest "
                  "message; replacement and expiry of the stored value are server-side "
                  "state and are not visible on the wire (the matrix records a dash for "
                  "that part of this row)."
                  + ("".join("\n" + d for d in details)))
        base = next((r for r in self.registrations if r.phantom_osc and r.last_notif_osc),
                    None)
        if base:
            conf.note("R9.9.2.1.2",
                      int.from_bytes(base.last_notif_osc.piv, "big")
                      > int.from_bytes(base.phantom_osc.piv, "big"),
                      "the phantom request consumes Sender Sequence Number %d and the "
                      "next protected message uses %d: the Sender Sequence Number "
                      "advances exactly once for the self-generated phantom request "
                      "(MO-15 §9.2.1)."
                      % (int.from_bytes(base.phantom_osc.piv, "big"),
                         int.from_bytes(base.last_notif_osc.piv, "big")))
        # R9.9.3.1.3: the same authenticated 'ph_req' is accepted again for the second
        # client registration — the replay exception is what makes that possible.
        verified_clients = [r for r in self.registrations
                            if r.phantom_result is not None and r.phantom_result.ok]
        identical = len(verified_clients) > 1 and len(
            {r.ir.get(1) for r in verified_clients}) == 1
        conf.note("R9.9.3.1.3", identical,
                  "both clients verify the same authenticated 'ph_req' value; a client "
                  "that applied the replay check here would reject the second "
                  "registration (MO-15 §9.3.1).")
        # R9.9.3.1.5: the phantom request is never put on the wire, and the client acts
        # on no unicast Token for it.
        on_wire = [p.get("frame") for p, m, o in self.messages
                   if o is not None and o.kid == self.vector.group.sender_id
                   and m.token == self.vector.phantom_token
                   and p.get("dport") != self.vector.group_port]
        conf.note("R9.9.3.1.5", not on_wire,
                  "the phantom request appears only inside the informative response and in "
                  "the multicast notifications addressed to the group port; no packet "
                  "sends it as a unicast request, and the client issues no response to it."
                  + ("" if not on_wire else "\nframes carrying it unicast: %s" % on_wire))
        # R9.9.3.1.8: the multicast Token comes from the informative response of the
        # verified observation, and the notifications use it.
        token_ok, token_detail = False, "no 'tp_info' to take the multicast Token from"
        if base and base.tp_info:
            token_ok = all(m.token == base.tp_info["token"]
                           for _, m, _ in self.notifications)
            token_detail = ("'tp_info' gives tpi_token = %s and every multicast "
                            "notification carries that Token; the association follows the "
                            "verified phantom request, not the unauthenticated outer "
                            "fields." % base.tp_info["token"].hex())
        conf.note("R9.9.3.1.8", token_ok, token_detail)
        conf.note("R9.9.3.1.6", ok and ok_present,
                  "the stored phantom kid / Partial IV / kid context verify every "
                  "notification of the observation.")
        conf.note("R9.9.3.1.9", ok and ok_present,
                  "the client-side verification of 'last_notif' succeeds; a tampered "
                  "'last_notif' is rejected in the negative test below while the valid "
                  "'ph_req' still verifies.")

    def check_notifications(self):
        conf = self.conf
        if not self.notifications:
            conf.record("R9.9.2.3.1", FAIL,
                        "no group-mode multicast notification in the capture")
            for row in ("R9.9.2.3.5", "R9.9.3.2.1", "R9.9.3.2.2", "R9.G7.3.1"):
                conf.record(row, FAIL, "no notification to check")
            return
        base = next((r for r in self.registrations if r.phantom_osc), None)
        if base is None:
            conf.record("R9.9.2.3.1", FAIL, "no verified phantom request to anchor the "
                       "notification AAD on")
            return
        request_kid = base.phantom_osc.kid or b""
        request_piv = base.phantom_osc.piv
        request_kid_context = (base.phantom_osc.kid_context
                               if base.phantom_osc.kid_context is not None else self.gid)
        details, ok, ok_piv = [], True, True
        pivs = []
        for packet, msg, osc in self.notifications:
            ctx = self.client_context(base.client.label)
            result = verify_group(msg, ctx, request_kid=request_kid, request_piv=request_piv,
                                  request_kid_context=request_kid_context, is_request=False)
            if result.ok:
                self.signature_forms.add(result.signature_form)
            self.log("frame %s notification: %s -> %s (%s)"
                     % (packet.get("frame"), osc, result.ok, result.note))
            if not result.ok:
                ok = False
                details.append("frame %s: %s" % (packet.get("frame"), result.note))
                continue
            if not osc.group:
                ok = False
                details.append("frame %s: Group Flag not set" % packet.get("frame"))
            if msg.token != self.vector.phantom_token:
                ok = False
                details.append("frame %s: Token %s, every notification carries the phantom "
                               "Token %s" % (packet.get("frame"), msg.token.hex(),
                                             self.vector.phantom_token.hex()))
            if msg.mtype != 1:
                ok = False
                details.append("frame %s: Type %d, MO-15 §4.3 requires Non-confirmable"
                               % (packet.get("frame"), msg.mtype))
            if msg.opt(OPT_OBSERVE) is None:
                ok = False
                details.append("frame %s: no Observe Option" % packet.get("frame"))
            pivs.append(int.from_bytes(osc.piv, "big"))
            self.log("frame %s inner: %s" % (packet.get("frame"), result.plaintext))
        # R9.9.2.3.5 / R9.G7.3.1: the first wire notification must carry a fresh PIV and
        # every subsequent notification a different one, and all verify with the frozen
        # phantom tuple.
        if pivs:
            first_wire = pivs[0]
            phantom_piv = int.from_bytes(request_piv, "big")
            expected_first = self.vector.expected.get("sequence_numbers", {}).get(
                "first_wire_notification")
            if expected_first is not None and first_wire != expected_first:
                ok_piv = False
                details.append("first wire notification PIV %d, expected %d "
                               "(phantom 501, INIT_NOTIF 502, first wire notification 503 "
                               "as agreed)" % (first_wire, expected_first))
            if first_wire <= phantom_piv:
                ok_piv = False
                details.append("first wire notification PIV %d does not advance past the "
                               "phantom PIV %d" % (first_wire, phantom_piv))
            if len(set(pivs)) != len(pivs):
                ok_piv = False
                details.append("repeated Partial IV among the notifications: %s" % pivs)
        conf.note("R9.9.2.3.1", ok,
                  "every multicast notification carries the Group Flag and independently "
                  "verifies in the group mode; there is no plaintext or pairwise fallback.")
        conf.note("R9.9.2.3.5", ok and ok_piv,
                  "Partial IVs seen on the wire: %s; each response after the first carries "
                  "its own Sender Sequence Number (GO-28 §7.3 Step 3)."
                  % ", ".join(str(p) for p in pivs)
                  + ("".join("\n" + d for d in details)))
        conf.note("R9.9.3.2.1", ok,
                  "every multicast notification decrypts and its countersignature verifies "
                  "(GO-28 §7.4); a one-byte tamper is rejected in the negative test below.")
        conf.note("R9.9.3.2.2", ok,
                  "each notification verifies with request_kid=%s, request_piv=%s and "
                  "request_kid_context=%s taken from the phantom request, and fails when "
                  "any of the three is altered (negative test below)."
                  % (request_kid.hex(), request_piv.hex(), request_kid_context.hex()))
        conf.note("R9.G7.3.1", ok and ok_piv,
                  "all notifications of the long exchange verify with the stored request "
                  "'kid' and 'kid context' and carry distinct response Partial IVs.")

    # -- AAD construction (GO-28 §3.4) -----------------------------------
    def check_aad_structure(self):
        """GO-28 §3.4: the external_aad really is a bstr-wrapped nine-element array with the
        specified content, and every field changes it."""
        conf = self.conf
        ctx = self.vector.group
        sample = next((r for r in self.registrations if r.phantom_osc), None)
        if sample is None:
            for row in ("R9.G3.4.1", "R9.G3.4.2", "R9.G3.4.3", "R9.G3.4.4"):
                conf.record(row, FAIL, "no verified group message to inspect")
            return
        osc = sample.phantom_osc
        aad = ctx.aad(osc.kid or b"", osc.piv, b"", self.gid, osc.raw)
        try:
            array, end = cbor_decode(aad, 0)
        except CborError as error:
            conf.record("R9.G3.4.1", FAIL, "external_aad does not decode: %s" % error)
            return
        ok_shape = (end == len(aad) and isinstance(array, list) and len(array) == 9
                    and array[0] == OSCORE_VERSION)
        conf.note("R9.G3.4.1", ok_shape,
                  "external_aad = bstr .cbor aad_array is a CBOR byte string wrapping a "
                  "nine-element array (GO-28 §3.4 Figure 2):\n%s" % aad.hex())
        names = ["alg_aead", "alg_group_enc", "alg_signature",
                 "alg_pairwise_key_agreement"]
        algorithms_ok = isinstance(array[1], list) and len(array[1]) == 4
        if algorithms_ok:
            algorithms_ok = all(isinstance(v, int) or v is None for v in array[1])
        conf.note("R9.G3.4.2", algorithms_ok,
                  "the algorithms array holds %s, with the CBOR simple value null where an "
                  "algorithm is not set in the Common Context."
                  % ", ".join("%s=%s" % (n, "null" if v is None else v)
                              for n, v in zip(names, array[1])))
        # R9.G3.4.4: the two credentials are CBOR byte strings.
        creds_ok = (isinstance(array[7], bytes) and isinstance(array[8], bytes)
                    and array[7] == ctx.sender_cred and array[8] == ctx.gm_cred
                    and cbor_is_canonical(cbor_encode(array[7])))
        conf.note("R9.G3.4.4", creds_ok,
                  "sender_cred (%d octets) and gm_cred (%d octets) are carried as CBOR byte "
                  "strings in their original binary form."
                  % (len(array[7]) if isinstance(array[7], bytes) else -1,
                     len(array[8]) if isinstance(array[8], bytes) else -1))

    def check_option_bound_aad(self):
        """R9.G3.4.3: the 'OSCORE_option' element is the finalized option value of *this*
        message, and substituting the empty byte string breaks verification (the Java
        Java peer deviation)."""
        conf = self.conf
        base = next((r for r in self.registrations if r.phantom_osc), None)
        if base is None:
            conf.record("R9.G3.4.3", FAIL, "no verified phantom request")
            return
        ctx = self.client_context(base.client.label)
        osc = base.phantom_osc
        good = verify_group(base.phantom, ctx, request_kid=osc.kid or b"", request_piv=osc.piv,
                            request_kid_context=self.gid, is_request=True)
        empty = verify_group(base.phantom, ctx, request_kid=osc.kid or b"",
                             request_piv=osc.piv, request_kid_context=self.gid,
                             is_request=True, oscore_option_override=b"")
        conf.note("R9.G3.4.3", good.ok and not empty.ok,
                  "the phantom request verifies with OSCORE_option = %s (the finalized\n"
                  "option value of that very message) and fails with OSCORE_option = h'':\n"
                  "%s.  This is a known Java peer deviation."
                  % (osc.raw.hex(), empty.note))
        # the same for a notification
        if self.notifications:
            packet, msg, nosc = self.notifications[0]
            pok = verify_group(msg, ctx, request_kid=osc.kid or b"", request_piv=osc.piv,
                               request_kid_context=self.gid, is_request=False)
            pempty = verify_group(msg, ctx, request_kid=osc.kid or b"", request_piv=osc.piv,
                                  request_kid_context=self.gid, is_request=False,
                                  oscore_option_override=b"")
            conf.note("R9.G3.4.3", conf.rows.get("R9.G3.4.3", (SKIP, ""))[0] != FAIL
                      and pok.ok and not pempty.ok,
                      "the same holds for the multicast notification: it verifies with its "
                      "own option value and fails with h''.")

    # -- negative tests ---------------------------------------------------
    def check_tamper(self):
        """Authenticity must actually be enforced: one altered byte, or one altered AAD
        field, and the message must stop verifying."""
        conf = self.conf
        base = next((r for r in self.registrations if r.phantom_osc), None)
        if base is None:
            for row in ("R9.9.3.1.7", "R9.G7.2.1", "R9.G7.4.1"):
                conf.record(row, FAIL, "no verified message to tamper with")
            return
        ctx = self.client_context(base.client.label)
        kid = base.phantom_osc.kid or b""
        piv = base.phantom_osc.piv
        details, all_rejected = [], True
        named = {}

        def rejected(name, result, row=None):
            nonlocal all_rejected
            if result.ok:
                all_rejected = False
                details.append("%s was ACCEPTED" % name)
            else:
                self.log("tamper %s rejected: %s" % (name, result.note))
            if row:
                named.setdefault(row, []).append(result.ok)
            return not result.ok

        # 1. one flipped ciphertext bit of the phantom request
        tampered = CoapMessage(base.phantom.mtype, base.phantom.code, base.phantom.mid,
                               base.phantom.token, base.phantom.options,
                               flip(base.phantom.payload, 0))
        rejected("one flipped ciphertext bit of ph_req",
                 verify_group(tampered, ctx, request_kid=kid, request_piv=piv,
                              request_kid_context=self.gid, is_request=True))
        # 2. one flipped bit of the encrypted countersignature of the phantom request
        sig_off = len(base.phantom.payload) - signature_length(self.vector.group.signature_alg)
        tampered = CoapMessage(base.phantom.mtype, base.phantom.code, base.phantom.mid,
                               base.phantom.token, base.phantom.options,
                               flip(base.phantom.payload, sig_off))
        rejected("one flipped countersignature bit of ph_req",
                 verify_group(tampered, ctx, request_kid=kid, request_piv=piv,
                              request_kid_context=self.gid, is_request=True))
        # 3. the AAD fields of the phantom request (R9.9.2.3.2-.4)
        for label, kwargs, row in (
                ("request_kid", dict(request_kid=flip(kid, 0)), "R9.9.2.3.2"),
                ("request_piv", dict(request_piv=flip(piv, -1)), "R9.9.2.3.3"),
                ("request_kid_context", dict(request_kid_context=flip(self.gid, 0)),
                 "R9.9.2.3.4")):
            arguments = dict(request_kid=kid, request_piv=piv,
                             request_kid_context=self.gid, is_request=True)
            arguments.update(kwargs)
            rejected("altered %s of ph_req" % label,
                     verify_group(base.phantom, ctx, **arguments), row=row)
        # 4. a tampered last_notif, while the valid ph_req still verifies
        if base.last_notif:
            tampered = CoapMessage(base.last_notif.mtype, base.last_notif.code,
                                   base.last_notif.mid, base.last_notif.token,
                                   base.last_notif.options,
                                   flip(base.last_notif.payload, 0))
            rejected("one flipped ciphertext bit of last_notif",
                     verify_group(tampered, ctx, request_kid=kid, request_piv=piv,
                                  request_kid_context=self.gid, is_request=False))
            still_ok = verify_group(base.phantom, ctx, request_kid=kid, request_piv=piv,
                                    request_kid_context=self.gid, is_request=True)
            if not still_ok.ok:
                all_rejected = False
                details.append("the valid ph_req stopped verifying after the last_notif "
                               "tamper test")
        # 5. a tampered notification, and a replayed one
        for index, (packet, msg, nosc) in enumerate(self.notifications):
            tampered = CoapMessage(msg.mtype, msg.code, msg.mid, msg.token, msg.options,
                                   flip(msg.payload, 0))
            rejected("frame %s one flipped ciphertext bit" % packet.get("frame"),
                     verify_group(tampered, ctx, request_kid=kid, request_piv=piv,
                                  request_kid_context=self.gid, is_request=False))
            break
        if len(self.notifications) > 1:
            first_packet, first_msg, _ = self.notifications[0]
            replayed = verify_group(first_msg, ctx, request_kid=kid, request_piv=piv,
                                    request_kid_context=self.gid, is_request=False)
            if not replayed.ok:
                self.log("replay of an earlier notification rejected: %s" % replayed.note)
            else:
                # An out-of-order replay is only rejected by the replay window, which is
                # internal state; record it rather than failing on a wire check.
                self.notes.append(
                    "the first notification verifies again on its own; replay rejection is "
                    "an internal replay-window assertion (R9.9.3.1.4, R9.G7.4.2), not "
                    "observable from a capture")
        for row, element, value in (
                ("R9.9.2.3.2", "request_kid", "the phantom request 'kid' %s" % kid.hex()),
                ("R9.9.2.3.3", "request_piv",
                 "the phantom request Partial IV %s" % piv.hex()),
                ("R9.9.2.3.4", "request_kid_context",
                 "the phantom request 'kid context' (Gid) %s" % self.gid.hex())):
            outcomes = named.get(row, [])
            conf.note(row, bool(outcomes) and not any(outcomes),
                      "the AAD reconstructs only with %s = %s: the message verifies with "
                      "that value and fails as soon as it is altered by one bit."
                      % (element, value))
        stored_used = all(row in self.conf.rows and self.conf.rows[row][0] == PASS
                          for row in ("R9.9.2.3.2", "R9.9.2.3.3", "R9.9.2.3.4"))
        conf.note("R9.G7.4.2", stored_used,
                  "every response of the long exchange verifies with the stored request "
                  "'kid' and 'kid context' and fails when the stored tuple is "
                  "substituted.  The Response Number itself advances only on a successful "
                  "verification; that is internal state (GO-28 §7.4) and is checked by a "
                  "protocol-unit test, not from a capture.")
        conf.note("R9.9.3.1.7", all_rejected,
                  "every tampered message fails verification, so a client that fails to "
                  "verify a phantom request must retry or withdraw — no phantom tuple, "
                  "multicast Token or delivered notification is retained."
                  + ("".join("\n" + d for d in details)))
        conf.note("R9.G7.2.1", all_rejected,
                  "a failed signature stops processing: the phantom request is rejected "
                  "before any plaintext is used.")
        conf.note("R9.G7.4.1", all_rejected,
                  "a modified ciphertext or signature is rejected; the Response Number is "
                  "only advanced on a successful verification (GO-28 §7.4).")
        conf.note("R9.9.3.1.2", conf.rows.get("R9.9.3.1.2", (SKIP, ""))[0] != FAIL
                  and all_rejected,
                  "the valid phantom request verifies and its one-byte-tampered copy does "
                  "not.")

    def check_expected(self):
        """R9.10.1 / R9.10.4: the observable sequence matches the vector."""
        conf = self.conf
        expected = self.vector.expected
        seq = expected.get("sequence_numbers", {})
        details, ok = [], True
        base = next((r for r in self.registrations if r.phantom_osc), None)
        phantom_piv = int.from_bytes(base.phantom_osc.piv, "big") if base else None
        if base and base.last_notif_osc:
            init_piv = int.from_bytes(base.last_notif_osc.piv, "big")
        else:
            init_piv = None
        wire = [int.from_bytes(osc.piv, "big") for _, _, osc in self.notifications]
        for name, value, observed in (
                ("phantom request", seq.get("phantom_request"), phantom_piv),
                ("INIT_NOTIF (last_notif)", seq.get("init_notification"), init_piv),
                ("first wire notification", seq.get("first_wire_notification"),
                 wire[0] if wire else None)):
            if value is not None and observed != value:
                ok = False
                details.append("%s: observed SN %s, the §10-derived vector says %s"
                               % (name, observed, value))
        # MO-15 §10 Figure 7 prints the first wire notification with Partial IV 0x01f6;
        # that is the INIT_NOTIF.  the agreed reading is: INIT_NOTIF consumes
        # 502, so the first later wire notification consumes 503.
        if phantom_piv is not None and wire and wire[0] == phantom_piv + 1:
            ok = False
            details.append("the first wire notification reuses the INIT_NOTIF Sequence "
                           "Number %d; Figure 7's 0x01f6 is the INIT_NOTIF, so the first "
                           "later wire notification must be %d (as agreed)"
                           % (wire[0], phantom_piv + 2))
        conf.note("R9.10.4", ok,
                  "Sender Sequence Numbers: phantom %s, INIT_NOTIF %s, first wire "
                  "notification %s — the corrected reading of MO-15 §10 Figure 7 "
                  "(as agreed).\n%s"
                  % (phantom_piv, init_piv, wire[0] if wire else None,
                     "\n".join(details)))
        # The representation goes 1234 -> 5678 (MO-15 §10): INIT_NOTIF stores and
        # returns the initial value, the first wire notification carries the new one.
        # The stored value is the server's *pre-notification* baseline, which the draft
        # leaves free (MO-15 §4.1 Step 6), so the vector may declare it separately as
        # `initial_value`; the failure detail names both sets to stay diagnosable.
        values_ok, seen, value_details = True, [], []
        if base is not None and base.last_notif_result is not None \
                and base.last_notif_result.ok:
            stored = base.last_notif_result.plaintext.payload
            seen.append("last_notif=%s" % stored.decode("utf-8", "replace"))
            if stored not in self.vector.values \
                    and stored not in self.vector.initial_value:
                values_ok = False
                value_details.append(
                    "the stored last_notif carries %r, which is neither one of the §10 "
                    "values %s nor the declared pre-notification baseline %s" % (
                        stored,
                        [v.decode() for v in self.vector.values],
                        [v.decode() for v in self.vector.initial_value]))
        ctx = self.client_context(base.client.label) if base else None
        for packet, msg, osc in self.notifications:
            if ctx is None:
                break
            result = verify_group(msg, ctx, request_kid=base.phantom_osc.kid or b"",
                                  request_piv=base.phantom_osc.piv,
                                  request_kid_context=self.gid, is_request=False)
            if result.ok:
                seen.append("notif#%s=%s" % (packet.get("frame"),
                                             result.plaintext.payload.decode(
                                                 "utf-8", "replace")))
        first_change = self.vector.expected.get("notifications", [{}])
        wanted = first_change[0].get("value") if first_change else None
        if wanted is not None and len(seen) > 1 and not seen[1].endswith("=" + wanted):
            values_ok = False
            value_details.append("the first wire notification carries %s, MO-15 §10 has "
                                 "the representation change to %r" % (seen[1], wanted))
        conf.note("R9.10.1", ok and values_ok,
                  "the stored INIT_NOTIF and the wire notifications decrypt to the §10 "
                  "representation values: %s.  MO-15 §10 fixes the 1234 -> 5678 change; a "
                  "longer demonstration run sends further notifications so that more than "
                  "one response carries its own Partial IV, and those follow the run's "
                  "counter (see expected.notifications in the vector)."
                  % ", ".join(seen)
                  + "".join("\n" + d for d in value_details))


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------

def summarise_trace(vector, packets):
    """`--emit-trace`: the decoded messages of a capture as JSON, so the verifier can run
    without re-parsing the capture."""
    out = []
    for packet in packets:
        raw = bytes.fromhex(packet["payload"])
        entry = {k: v for k, v in packet.items() if k != "payload"}
        try:
            msg = parse_coap(raw)
            entry["coap"] = {
                "type": msg.mtype, "code": msg.code, "mid": msg.mid,
                "token": msg.token.hex(), "payload": msg.payload.hex(),
                "options": [[n, v.hex()] for n, v in msg.options],
            }
            option = msg.oscore_option()
            if option is not None:
                osc = parse_oscore_option(option)
                entry["oscore"] = {"raw": option.hex(), "group": osc.group,
                                   "piv": osc.piv.hex(),
                                   "kid": osc.kid.hex() if osc.kid is not None else None,
                                   "kid_context": (osc.kid_context.hex()
                                                   if osc.kid_context is not None
                                                   else None)}
        except VerifyError as error:
            entry["error"] = str(error)
        out.append(entry)
    return out


def trace_to_packets(trace):
    """Turn a `--emit-trace` JSON document back into the packet list the analysis uses."""
    packets = []
    for entry in trace:
        coap = entry.get("coap")
        if not coap:
            continue
        msg = CoapMessage(coap["type"], coap["code"], coap["mid"],
                          bytes.fromhex(coap["token"]),
                          [(n, bytes.fromhex(v)) for n, v in coap["options"]],
                          bytes.fromhex(coap["payload"]))
        packets.append({**{k: v for k, v in entry.items()
                           if k not in ("coap", "oscore")},
                        "payload": serialize_coap(msg).hex()})
    return packets


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Independent verifier for the draft-15 §9/§10 secure Multicast "
                    "Observe profile.")
    parser.add_argument("inputs", nargs="*", metavar="PCAP|JSON",
                        help="capture files (pcap/pcapng) or JSON traces to verify")
    parser.add_argument("--vector", metavar="FILE",
                        help="the Section-10-derived test vector (JSON) giving every "
                             "chosen input and the expected sequence")
    parser.add_argument("--emit-trace", action="store_true",
                        help="decode the inputs to a JSON trace and print it, then exit")
    parser.add_argument("--json", action="store_true",
                        help="print the per-row result table as JSON")
    parser.add_argument("--list-rows", action="store_true",
                        help="print the conformance rows this tool knows about and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print every message as it is decoded and verified")
    args = parser.parse_args(argv)

    if args.list_rows:
        for row in sorted(ROW_TEXT):
            print("%-12s %s" % (row, ROW_TEXT[row]))
        return 0
    if not args.inputs:
        parser.error("no capture or trace given")
    if not args.vector and not args.emit_trace:
        parser.error("--vector is required: the verifier needs the declared test inputs")

    packets = []
    for path in args.inputs:
        if path.endswith(".json"):
            with open(path) as handle:
                packets.extend(trace_to_packets(json.load(handle)))
        else:
            packets.extend(read_pcap(path))
    if not packets:
        sys.stderr.write("gosc_verify: no UDP datagrams found in the inputs\n")
        return 2

    if args.emit_trace:
        json.dump(summarise_trace(args.vector and load_vector(args.vector), packets),
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    vector = load_vector(args.vector)
    analysis = Analysis(vector, packets, verbose=args.verbose)
    conf = analysis.run()

    rows = {row: {"status": conf.rows[row][0], "requirement": ROW_TEXT.get(row, ""),
                  "detail": conf.rows[row][1]} for row in conf.order}
    if args.json:
        json.dump({"vector": args.vector, "inputs": args.inputs, "rows": rows,
                   "notes": analysis.notes,
                   "countersignature_form": sorted(
                       f for f in analysis.signature_forms if f)},
                  sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("gosc_verify — independent check of the §9/§10 secure profile")
        print("  vector : %s" % args.vector)
        print("  inputs : %s (%d UDP datagrams)" % (", ".join(args.inputs), len(packets)))
        print()
        conf.render()
        if analysis.signature_forms:
            print("\ncountersignature: RFC 9338 §3.3 Countersign_structure, %s matched "
                  "(COSE alg %d = %s)"
                  % ("/".join(sorted(f for f in analysis.signature_forms if f)),
                     vector.group.signature_alg,
                     "EdDSA" if vector.group.signature_alg == ALG_EDDSA else "ES256"))
        if analysis.notes:
            print("\nnotes:")
            for note in analysis.notes:
                print("  - %s" % note)
    return 1 if conf.failed else 0


if __name__ == "__main__":
    sys.exit(main())
