#!/usr/bin/env python3
"""Unit tests for tools/gosc_verify.py — the independent §9/§10 verifier.

Run:  python3 tools/test_gosc_verify.py

Coverage:

  * published header-compression vectors
      - draft-ietf-core-oscore-groupcomm-28 §4.3.1 (group mode) and §4.3.2 (pairwise mode)
      - RFC 8613 §6.3
    These are the Group OSCORE test vectors the draft actually publishes.  GO-28 -28 has
    no appendix of full group-mode cryptographic vectors: §4.3 fixes the COSE object and
    the compressed output but not the Security Context, so the ciphertext and the
    countersignature cannot be recomputed from the text.  That limit is asserted here, so
    a future revision of the draft with real vectors will fail this test instead of
    passing unnoticed.
  * HKDF (RFC 5869 test vectors, which RFC 8613 §3.2.1 builds on)
  * the Security Context derivation of RFC 8613 §3.2.1 and of GO-28 §2.3 / §2.1.9
  * the nonce construction of RFC 8613 §5.2 and of GO-28 §3.3
  * the external_aad of RFC 8613 §5.4 and of GO-28 §3.4, including the CBOR null for an
    algorithm that is not set
  * the countersignature and its keystream (RFC 9338 §3.3, GO-28 §4.2)
  * protect / verify round trips and one-bit tamper rejection
  * CBOR, CoAP and the transport-independent encoding of MO-15 §4.2.2
  * the capture reader, on a hand-built pcap
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gosc_verify as G  # noqa: E402

VECTOR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                           "docs", "secure", "section10-vector.json")
PCAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                         "evidence", "section10", "section10.pcap")

CIPHERTEXT = bytes.fromhex("aea0155667924dff8a24e4cb35b9")
SIGNATURE64 = bytes(range(64))


# ---------------------------------------------------------------------------
# published vectors
# ---------------------------------------------------------------------------

class TestPublishedCompressionVectors(unittest.TestCase):
    """draft-ietf-core-oscore-groupcomm-28 §4.3 and RFC 8613 §6.3."""

    def test_go28_group_mode_request(self):
        # §4.3.1: kid = 0x25, Partial IV = 5, kid context = 0x44616c.
        # "Flag byte: 0b00111001 = 0x39", "Option Value: 0x39 05 03 44 61 6c 25",
        # "Payload: ciphertext (14 bytes) + size of the encrypted countersignature".
        option, payload = G.compress_cose(
            b"", {4: b"\x25", 6: b"\x05", 10: b"\x44\x61\x6c"}, CIPHERTEXT,
            SIGNATURE64, group=True)
        self.assertEqual(option, bytes.fromhex("39050344616c25"))
        self.assertEqual(option[0], 0x39)
        self.assertEqual(payload[:14], CIPHERTEXT)
        # §4.3 states the COSE_Countersignature0 is 64 bytes in these examples.
        self.assertEqual(len(payload), 14 + 64)

    def test_go28_group_mode_response(self):
        # §4.3.1: kid = 0x52, no Partial IV.
        # "Flag byte: 0b00101000 = 0x28", "Option Value: 0x28 52".
        option, payload = G.compress_cose(
            b"", {4: b"\x52", 12: SIGNATURE64}, CIPHERTEXT, SIGNATURE64, group=True)
        self.assertEqual(option, bytes.fromhex("2852"))
        self.assertEqual(option[0], 0x28)
        self.assertEqual(len(payload), 14 + 64)

    def test_go28_pairwise_mode_request(self):
        # §4.3.2: same fields, Group Flag 0.  "Flag byte: 0b00011001 = 0x19",
        # "Option Value: 0x19 05 03 44 61 6c 25", payload is the ciphertext alone.
        option, payload = G.compress_cose(
            b"", {4: b"\x25", 6: b"\x05", 10: b"\x44\x61\x6c"}, CIPHERTEXT, group=False)
        self.assertEqual(option, bytes.fromhex("19050344616c25"))
        self.assertEqual(payload, CIPHERTEXT)
        self.assertEqual(option[0] & G.FLAG_GROUP, 0)

    def test_go28_pairwise_mode_response(self):
        # §4.3.2: no 'kid', no Partial IV.  "Flag byte: 0b00000000 = 0x00",
        # "Option Value: 0x (0 bytes)".
        option, payload = G.compress_cose(b"", {}, CIPHERTEXT, group=False)
        self.assertEqual(option, b"")
        self.assertEqual(payload, CIPHERTEXT)

    def test_go28_publishes_no_full_group_cryptographic_vectors(self):
        """The §4.3 examples fix the compression but not the keying material.

        The countersignature in the printed COSE object is itself truncated in the text,
        so no ciphertext in §4.3 can be recomputed.  If a later revision of the draft adds
        real group-mode vectors this assertion is what has to be revisited.
        """
        import re
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs",
                            "secure", "draft-ietf-core-oscore-groupcomm-28.txt")
        if not os.path.exists(path):
            self.skipTest("the pinned draft text is not available")
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        self.assertNotIn("Appendix D.  Test Vectors", text)
        # The printed countersignature of the first §4.3.1 example is 90 hex characters,
        # i.e. fewer than the 64 octets §4.3 itself states.
        match = re.search(r"Countersignature0 version 2\s*/\s*12\s*:\s*h'([0-9a-f]+)",
                          text, re.S)
        self.assertIsNotNone(match)
        self.assertLess(len(match.group(1)) // 2, 64)

    def test_rfc8613_section_6_3(self):
        cases = [
            # (unprotected map, expected flag byte, expected option value)
            ({4: b"\x25", 6: b"\x05"}, 0x09, "090525"),
            ({4: b"", 6: b"\x00"}, 0x09, "0900"),
            ({4: b"", 6: b"\x05", 10: b"\x44\x61\x6c\x65\x6b"}, 0x19,
             "19050544616c656b"),
            ({}, 0x00, ""),
            ({6: b"\x07"}, 0x01, "0107"),
        ]
        for unprotected, flag, option_hex in cases:
            with self.subTest(unprotected=unprotected):
                option, payload = G.compress_cose(b"", unprotected, CIPHERTEXT)
                self.assertEqual(option[0] if option else 0x00, flag)
                self.assertEqual(option.hex(), option_hex)
                self.assertEqual(payload, CIPHERTEXT)

    def test_group_flag_is_the_sixth_least_significant_bit(self):
        """GO-28 §4.1 / §15.1 Table 1: the Group Flag is the sixth least significant bit."""
        option = G.compress_oscore_option(b"\x05", None, b"\x25", True)
        self.assertEqual(option[0], 0x29)  # 0x20 | 0x08 | 0x01
        self.assertEqual(option[0] & G.FLAG_GROUP, G.FLAG_GROUP)
        self.assertEqual(G.FLAG_GROUP, 0x20)
        self.assertEqual(G.FLAG_RESERVED_MASK, 0xC0)  # bits 7 and 8 stay reserved

    def test_reserved_flag_bits_are_rejected(self):
        for flags in (0x40, 0x80, 0xC0):
            with self.subTest(flags=flags):
                with self.assertRaises(G.VerifyError):
                    G.parse_oscore_option(bytes([flags]) + b"\x05")


# ---------------------------------------------------------------------------
# HKDF
# ---------------------------------------------------------------------------

class TestHkdf(unittest.TestCase):
    """RFC 5869 Appendix A, the test vectors RFC 8613 §3.2.1's HKDF is built on."""

    def test_rfc5869_test_case_1(self):
        # A.1: SHA-256, IKM 0x0b*22, salt 000102...0c, info f0f1...f9, L 42.
        okm = G.hkdf(bytes.fromhex("000102030405060708090a0b0c"),
                     bytes.fromhex("0b" * 22),
                     bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(okm.hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
                         "ecc4c5bf34007208d5b887185865")

    def test_rfc5869_test_case_3(self):
        # A.3: zero-length salt and info.
        okm = G.hkdf(b"", bytes.fromhex("0b" * 22), b"", 42)
        self.assertEqual(okm.hex(),
                         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f"
                         "3c738d2d9d201395faa4b61a96c8")

    def test_rfc8613_empty_salt_is_zeroes(self):
        """RFC 8613 §3.2.1: an absent salt equals the empty byte string, which RFC 5869
        §2.2 defines as HashLen zero octets."""
        self.assertEqual(G.hkdf(b"", b"secret", b"info", 16),
                         G.hkdf(bytes(32), b"secret", b"info", 16))

    def test_unsupported_hkdf_is_refused(self):
        with self.assertRaises(G.VerifyError):
            G.hkdf(b"", b"secret", b"info", 16, alg=-37)  # HKDF SHA-512


# ---------------------------------------------------------------------------
# security contexts
# ---------------------------------------------------------------------------

class TestContextDerivation(unittest.TestCase):
    def test_info_array_shape(self):
        """RFC 8613 §3.2.1: info = [id, id_context, alg_aead, type, L]."""
        ctx = G.PairwiseContext(bytes.fromhex("0102030405060708090a0b0c0d0e0f21"),
                                bytes.fromhex("9e7ca92223786340"),
                                sender_id=bytes.fromhex("01"),
                                recipient_id=bytes.fromhex("00"))
        self.assertEqual(len(ctx.sender_key), 16)
        self.assertEqual(len(ctx.recipient_key), 16)
        self.assertEqual(len(ctx.common_iv), 13)  # AES-CCM-16-64-128 nonce length
        self.assertNotEqual(ctx.sender_key, ctx.recipient_key)
        # Recompute the Sender Key by hand from the published inputs.
        info = G.cbor_encode([bytes.fromhex("01"), None, 10, "Key", 16])
        self.assertEqual(ctx.sender_key,
                         G.hkdf(ctx.master_salt, ctx.master_secret, info, 16))
        info = G.cbor_encode([b"", None, 10, "IV", 13])
        self.assertEqual(ctx.common_iv,
                         G.hkdf(ctx.master_salt, ctx.master_secret, info, 13))

    def test_group_context_uses_the_group_encryption_algorithm(self):
        """GO-28 §2.3: with the Group Encryption Algorithm set, the 'alg_aead' element of
        the info array is that algorithm, and the Signature Encryption Key (GO-28 §2.1.9)
        uses an empty 'id', the type "SEKey" and L = the Group Encryption Algorithm's key
        length."""
        ctx = G.GroupContext(bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
                             bytes.fromhex("9e7ca92223786340"), bytes.fromhex("57ab2e"),
                             sender_id=bytes.fromhex("05"))
        salt = bytes.fromhex("9e7ca92223786340")
        secret = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        info = G.cbor_encode([bytes.fromhex("05"), bytes.fromhex("57ab2e"), 10, "Key", 16])
        self.assertEqual(ctx.sender_key, G.hkdf(salt, secret, info, 16))
        info = G.cbor_encode([b"", bytes.fromhex("57ab2e"), 10, "SEKey", 16])
        self.assertEqual(ctx.signature_encryption_key, G.hkdf(salt, secret, info, 16))
        # The Gid is the ID Context of the derivation.
        self.assertNotEqual(
            ctx.sender_key,
            G.GroupContext(secret, salt, bytes.fromhex("57ab2f"),
                           sender_id=bytes.fromhex("05")).sender_key)

    def test_signature_encryption_key_depends_on_the_gid(self):
        """GO-28 §4.2's info carries the ID Context, so a different Gid gives a different
        keystream for the same Partial IV."""
        salt, secret = bytes.fromhex("9e7ca92223786340"), bytes(range(16))
        a = G.GroupContext(secret, salt, bytes.fromhex("57ab2e"), sender_id=b"\x05")
        b = G.GroupContext(secret, salt, bytes.fromhex("57ab2f"), sender_id=b"\x05")
        self.assertNotEqual(a.keystream(b"\x01", b"\x05", False, 64),
                            b.keystream(b"\x01", b"\x05", False, 64))

    def test_keystream_info_shape(self):
        """GO-28 §4.2: info = [id, id_context, type, L]; salt is the Partial IV."""
        ctx = G.GroupContext(bytes(range(16)), bytes.fromhex("9e7ca92223786340"),
                             bytes.fromhex("57ab2e"), sender_id=b"\x05")
        expected = G.hkdf(b"\x01\xf6", ctx.signature_encryption_key,
                          G.cbor_encode([b"\x05", bytes.fromhex("57ab2e"), False, 64]), 64)
        self.assertEqual(ctx.keystream(b"\x01\xf6", b"\x05", False, 64), expected)
        # The request/response flag is part of the derivation.
        self.assertNotEqual(ctx.keystream(b"\x01\xf6", b"\x05", False, 64),
                            ctx.keystream(b"\x01\xf6", b"\x05", True, 64))


class TestNonce(unittest.TestCase):
    """RFC 8613 §5.2 Figure 8, and GO-28 §3.3."""

    def test_pairwise_nonce(self):
        iv = bytes.fromhex("00112233445566778899aabbcc")
        # RFC 8613 §5.2: the seed is S | padded ID_PIV | padded PIV, XORed with the IV.
        nonce = G.nonce_pairwise(b"\x65", b"\x01", iv)
        self.assertEqual(len(nonce), 13)
        # Figure 8: S | ID_PIV left-padded to nonce length - 6 | PIV left-padded to 5.
        seed = b"\x01" + bytes(6) + b"\x01" + bytes(4) + b"\x65"
        self.assertEqual(len(seed), 13)
        self.assertEqual(nonce, bytes(a ^ b for a, b in zip(seed, iv)))

    def test_group_nonce_keeps_the_pairwise_steps(self):
        """GO-28 §3.3 replaces only Step 4, so with a Common IV of exactly the nonce
        length the two constructions agree byte for byte."""
        iv = bytes.fromhex("00112233445566778899aabbcc")
        self.assertEqual(G.nonce_group(b"\x01\xf6", b"\x05", iv, 13),
                         G.nonce_pairwise(b"\x01\xf6", b"\x05", iv))

    def test_group_nonce_uses_only_the_first_x_bytes(self):
        """GO-28 §3.3: with a longer Common IV, only its first X bytes are XORed."""
        short = bytes.fromhex("00112233445566778899aabbcc")
        long = short + bytes.fromhex("ddeeff0011223344")
        self.assertEqual(G.nonce_group(b"\x01\xf6", b"\x05", long, 13),
                         G.nonce_group(b"\x01\xf6", b"\x05", short, 13))

    def test_id_piv_participates(self):
        iv = bytes.fromhex("00112233445566778899aabbcc")
        self.assertNotEqual(G.nonce_pairwise(b"\x05", b"\x01", iv),
                            G.nonce_pairwise(b"\x05", b"\x02", iv))


# ---------------------------------------------------------------------------
# additional authenticated data
# ---------------------------------------------------------------------------

class TestAdditionalAuthenticatedData(unittest.TestCase):
    def test_oscore_aad_is_five_elements(self):
        """RFC 8613 §5.4."""
        aad = G.aad_oscore(b"\x01", b"\x65", b"\xb1\x72", 10)
        array, end = G.cbor_decode(aad, 0)
        self.assertEqual(end, len(aad))
        self.assertEqual(array, [1, [10], b"\x01", b"\x65", b"\xb1\x72"])
        self.assertEqual(G.cbor_encode(array), aad)

    def test_group_aad_is_nine_elements(self):
        """GO-28 §3.4, Figure 2."""
        aad = G.aad_group(b"\x05", b"\x01\xf5", b"", b"\x57\xab\x2e", b"\x2a\x01\xf6\x05",
                          b"\x01\x02", b"\x03\x04", 10, 10, -8, -27)
        array, end = G.cbor_decode(aad, 0)
        self.assertEqual(end, len(aad))
        self.assertEqual(len(array), 9)
        self.assertEqual(array[0], 1)
        self.assertEqual(array[1], [10, 10, -8, -27])
        self.assertEqual(array[2], b"\x05")            # request_kid
        self.assertEqual(array[3], b"\x01\xf5")        # request_piv
        self.assertEqual(array[4], b"")                # options
        self.assertEqual(array[5], b"\x57\xab\x2e")    # request_kid_context
        self.assertEqual(array[6], b"\x2a\x01\xf6\x05")  # OSCORE_option
        self.assertEqual(array[7], b"\x01\x02")        # sender_cred, a CBOR byte string
        self.assertEqual(array[8], b"\x03\x04")        # gm_cred

    def test_unset_algorithms_are_cbor_null(self):
        """GO-28 §3.4: an algorithm that is not set in the Common Context MUST be the
        CBOR simple value null (0xf6)."""
        aad = G.aad_group(b"", b"", b"", b"", b"", b"", b"", 10, None, None, None)
        array, _ = G.cbor_decode(aad, 0)
        self.assertEqual(array[1], [10, None, None, None])
        self.assertIn(b"\xf6", aad)
        # AAD built this way must differ from one that omits the element entirely.
        self.assertNotEqual(aad, G.cbor_encode([1, [10], b"", b"", b"", b"", b"",
                                                b"", b""]))

    def test_credentials_are_byte_strings(self):
        """GO-28 §3.4: sender_cred and gm_cred are CBOR byte strings carrying the original
        binary credential."""
        cred = bytes.fromhex("a501781a636f6170733a2f2f646f6d61696e2e6578616d706c652e6f72")
        aad = G.aad_group(b"", b"", b"", b"", b"", cred, cred, 10, 10, -8, None)
        array, _ = G.cbor_decode(aad, 0)
        self.assertIsInstance(array[7], bytes)
        self.assertEqual(array[7], cred)
        self.assertEqual(array[8], cred)

    def test_every_aad_field_is_authenticated(self):
        """Changing any one element must change the AAD bytes."""
        base = dict(request_kid=b"\x05", request_piv=b"\x01\xf5", options=b"",
                    request_kid_context=b"\x57\xab\x2e", oscore_option=b"\x2a\x01\xf6\x05",
                    sender_cred=b"\x01", gm_cred=b"\x02", alg_aead=10, alg_group_enc=10,
                    alg_signature=-8, alg_pairwise_key_agreement=-27)
        reference = G.aad_group(**base)
        for field, changed in (
                ("request_kid", b"\x06"), ("request_piv", b"\x01\xf6"),
                ("options", b"\xb1\x72"), ("request_kid_context", b"\x57\xab\x2f"),
                ("oscore_option", b""), ("sender_cred", b"\x03"),
                ("gm_cred", b"\x04"), ("alg_aead", 11), ("alg_group_enc", 11),
                ("alg_signature", -7), ("alg_pairwise_key_agreement", None)):
            with self.subTest(field=field):
                variant = dict(base, **{field: changed})
                self.assertNotEqual(reference, G.aad_group(**variant))

    def test_enc_structure_wraps_the_external_aad(self):
        """RFC 9052 §5.1: the AEAD's AAD is the Enc_structure, not the bare external_aad."""
        external = G.aad_oscore(b"\x01", b"\x65", b"", 10)
        wrapped = G.enc_structure(external)
        self.assertNotEqual(external, wrapped)
        array, _ = G.cbor_decode(wrapped, 0)
        self.assertEqual(array[0], "Encrypt0")
        self.assertEqual(array[1], b"")
        self.assertEqual(array[2], external)


# ---------------------------------------------------------------------------
# countersignature
# ---------------------------------------------------------------------------

class TestCountersignature(unittest.TestCase):
    """RFC 9338 §3.3 as used by GO-28 §3.1."""

    def test_structure_shapes(self):
        aad = G.aad_group(b"", b"", b"", b"", b"", b"", b"", 10, 10, -8, None)
        four, _ = G.cbor_decode(
            G.countersign_structure("CounterSignature0", b"", aad, b"ct",
                                    include_sign_protected=False), 0)
        five, _ = G.cbor_decode(
            G.countersign_structure("CounterSignature0", b"", aad, b"ct",
                                    include_sign_protected=True), 0)
        self.assertEqual(four, ["CounterSignature0", b"", aad, b"ct"])
        self.assertEqual(five, ["CounterSignature0", b"", b"", aad, b"ct"])
        # RFC 9338 §3.3: the context string names the V2 form when other_fields is
        # present; GO-28 §3.1 fixes "CounterSignature0" for the abbreviated
        # countersignature over a COSE_Encrypt0.
        self.assertEqual(four[0], "CounterSignature0")

    def test_sign_and_verify_ed25519(self):
        private = G.private_key_from_seed(G.ALG_EDDSA, bytes(range(32)))
        public = private.public_key()
        signature = G.sign(G.ALG_EDDSA, private, b"to be signed")
        self.assertEqual(len(signature), 64)
        self.assertTrue(G.signature_verify(G.ALG_EDDSA, public, b"to be signed",
                                           signature))
        self.assertFalse(G.signature_verify(G.ALG_EDDSA, public, b"other", signature))
        flipped = bytearray(signature)
        flipped[0] ^= 1
        self.assertFalse(G.signature_verify(G.ALG_EDDSA, public, b"to be signed",
                                            bytes(flipped)))

    def test_sign_and_verify_es256(self):
        private = G.private_key_from_seed(G.ALG_ES256, bytes(range(32)))
        signature = G.sign(G.ALG_ES256, private, b"to be signed")
        self.assertEqual(len(signature), 64)  # r || s
        self.assertTrue(G.signature_verify(G.ALG_ES256, private.public_key(),
                                           b"to be signed", signature))

    def test_cose_algorithm_numbers(self):
        """RFC 9052 §4.1: ES256 is -7 and EdDSA is -8.  A profile that says -8 is Ed25519,
        not ECDSA P-256."""
        self.assertEqual(G.ALG_ES256, -7)
        self.assertEqual(G.ALG_EDDSA, -8)

    def test_credential_holds_the_ed25519_public_key(self):
        cred = bytes.fromhex(
            "a501781a636f6170733a2f2f7365727665722e6578616d706c652e636f6d02"
            "6673656e64657203781a636f6170733a2f2f636c69656e742e6578616d706c652e6f"
            "7267041a70004b4f08a101a401010327200621582077ec358c1d344e41ee0e87b8"
            "383d23a2099acd39bdf989ce45b52e887463389b")
        key = G.parse_credential(cred)
        self.assertEqual(key[G.COSE_KTY], G.COSE_KTY_OKP)
        self.assertEqual(key[G.COSE_KEY_CRV], G.COSE_CRV_ED25519)
        self.assertEqual(key[G.COSE_ALG], G.ALG_EDDSA)
        self.assertEqual(G.credential_x(cred).hex(),
                         "77ec358c1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b")


# ---------------------------------------------------------------------------
# end-to-end protect / verify
# ---------------------------------------------------------------------------

def make_group_context(seed=1):
    secret = bytes((seed + i) % 256 for i in range(16))
    return G.GroupContext(secret, bytes.fromhex("9e7ca92223786340"),
                         bytes.fromhex("57ab2e"),
                         sender_cred=bytes.fromhex("a5017819" + "00" * 25),
                         gm_cred=bytes.fromhex("a5017819" + "11" * 25),
                         sender_id=bytes.fromhex("05"), recipient_id=b"",
                         sender_private_key=G.private_key_from_seed(
                             G.ALG_EDDSA, bytes(range(32))),
                         recipient_pubkey=G.private_key_from_seed(
                             G.ALG_EDDSA, bytes(range(32))).public_key())


class TestGroupRoundTrip(unittest.TestCase):
    """Protect with the sender context, verify with the recipient context."""

    def setUp(self):
        self.sender = make_group_context()
        self.receiver = G.GroupContext(
            self.sender.master_secret, self.sender.master_salt, self.sender.gid,
            sender_cred=self.sender.sender_cred, gm_cred=self.sender.gm_cred,
            sender_id=b"", recipient_id=bytes.fromhex("05"),
            recipient_pubkey=G.private_key_from_seed(
                G.ALG_EDDSA, bytes(range(32))).public_key())
        self.assertEqual(self.sender.sender_key, self.receiver.recipient_key)

    def _protect(self, ctx, piv, is_request, **overrides):
        inner = G.InnerMessage(G.CODE_CONTENT,
                               [(G.OPT_OBSERVE, b"\x02")], b"5678")
        arguments = dict(request_kid=bytes.fromhex("05"),
                         request_piv=b"\x01\xf5",
                         request_kid_context=bytes.fromhex("57ab2e"),
                         outer_options=[], key=ctx.sender_key)
        arguments.update(overrides)
        return G.protect_group(ctx, inner, piv, bytes.fromhex("05"), is_request,
                               **arguments)

    def test_notification_round_trip(self):
        option, payload = self._protect(self.sender, 0x01F6, False)
        msg = G.CoapMessage(1, G.CODE_CONTENT, 0, b"\x7b",
                            [(G.OPT_OBSERVE, b"\x02"), (9, option)], payload)
        result = G.verify_group(msg, self.receiver, request_kid=bytes.fromhex("05"),
                                request_piv=b"\x01\xf5",
                                request_kid_context=bytes.fromhex("57ab2e"),
                                is_request=False)
        self.assertTrue(result.ok, result.note)
        self.assertEqual(result.plaintext.payload, b"5678")
        self.assertEqual(result.plaintext.code, G.CODE_CONTENT)
        self.assertEqual(result.signature_form, "5-element")

    def test_phantom_request_round_trip(self):
        inner = G.InnerMessage(G.CODE_GET, [(G.OPT_OBSERVE, b""),
                                            (G.OPT_URI_PATH, b"r")], b"")
        # The phantom request carries the Gid as its own 'kid context' (GO-28 §3.2), and
        # its Partial IV is the Sender Sequence Number it consumes, 501 = 0x01f5.  For
        # this request the AAD's request_kid and request_piv are its own Option fields.
        option, payload = G.protect_group(
            self.sender, inner, 501, bytes.fromhex("05"), True,
            request_kid=bytes.fromhex("05"), request_piv=b"\x01\xf5",
            request_kid_context=bytes.fromhex("57ab2e"), outer_options=[],
            key=self.sender.sender_key)
        self.assertEqual(G.parse_oscore_option(option).kid_context,
                         bytes.fromhex("57ab2e"))
        msg = G.CoapMessage(1, G.CODE_FETCH, 0, b"\x7b", [(9, option)], payload)
        result = G.verify_group(msg, self.receiver, request_kid=bytes.fromhex("05"),
                                request_piv=b"\x01\xf5",
                                request_kid_context=bytes.fromhex("57ab2e"),
                                is_request=True)
        self.assertTrue(result.ok, result.note)
        self.assertEqual(result.plaintext.code, G.CODE_GET)
        self.assertEqual(result.plaintext.opts(G.OPT_URI_PATH), [b"r"])

    def test_tampered_ciphertext_is_rejected(self):
        option, payload = self._protect(self.sender, 0x01F6, False)
        for index in (0, len(payload) // 2, len(payload) - 65):
            with self.subTest(index=index):
                broken = bytearray(payload)
                broken[index] ^= 0x01
                msg = G.CoapMessage(1, G.CODE_CONTENT, 0, b"\x7b",
                                    [(9, option)], bytes(broken))
                result = G.verify_group(msg, self.receiver,
                                        request_kid=bytes.fromhex("05"),
                                        request_piv=b"\x01\xf5",
                                        request_kid_context=bytes.fromhex("57ab2e"),
                                        is_request=False)
                self.assertFalse(result.ok)

    def test_tampered_signature_is_rejected(self):
        option, payload = self._protect(self.sender, 0x01F6, False)
        broken = bytearray(payload)
        broken[-1] ^= 0x01
        msg = G.CoapMessage(1, G.CODE_CONTENT, 0, b"\x7b", [(9, option)], bytes(broken))
        result = G.verify_group(msg, self.receiver, request_kid=bytes.fromhex("05"),
                                request_piv=b"\x01\xf5",
                                request_kid_context=bytes.fromhex("57ab2e"),
                                is_request=False)
        self.assertFalse(result.ok)
        self.assertIn("countersignature", result.note)

    def test_wrong_credential_fails(self):
        option, payload = self._protect(self.sender, 0x01F6, False)
        msg = G.CoapMessage(1, G.CODE_CONTENT, 0, b"\x7b", [(9, option)], payload)
        impostor = G.GroupContext(self.receiver.master_secret,
                                  self.receiver.master_salt, self.receiver.gid,
                                  sender_cred=bytes.fromhex("a5017819" + "00" * 25),
                                  gm_cred=bytes.fromhex("a5017819" + "22" * 25),
                                  recipient_id=bytes.fromhex("05"),
                                  recipient_pubkey=self.receiver.recipient_pubkey)
        result = G.verify_group(msg, impostor, request_kid=bytes.fromhex("05"),
                                request_piv=b"\x01\xf5",
                                request_kid_context=bytes.fromhex("57ab2e"),
                                is_request=False)
        self.assertFalse(result.ok)

    def test_pairwise_mode_message_is_refused_in_group_context(self):
        """A message without the Group Flag is not processed as a group-mode message."""
        option, payload = self._protect(self.sender, 0x01F6, False)
        option = bytearray(option)
        option[0] &= ~G.FLAG_GROUP & 0xFF
        msg = G.CoapMessage(1, G.CODE_CONTENT, 0, b"\x7b",
                            [(9, bytes(option))], payload)
        with self.assertRaises(G.VerifyError) as raised:
            G.verify_group(msg, self.receiver, request_kid=bytes.fromhex("05"),
                           request_piv=b"\x01\xf5",
                           request_kid_context=bytes.fromhex("57ab2e"), is_request=False)
        self.assertIn("Group Flag", str(raised.exception))

    def test_empty_oscore_option_in_the_aad_is_rejected(self):
        """Java peer deviation: OSCORE_option must be the finalized option, not h''."""
        option, payload = self._protect(self.sender, 0x01F6, False)
        msg = G.CoapMessage(1, G.CODE_CONTENT, 0, b"\x7b", [(9, option)], payload)
        good = G.verify_group(msg, self.receiver, request_kid=bytes.fromhex("05"),
                              request_piv=b"\x01\xf5",
                              request_kid_context=bytes.fromhex("57ab2e"),
                              is_request=False)
        empty = G.verify_group(msg, self.receiver, request_kid=bytes.fromhex("05"),
                               request_piv=b"\x01\xf5",
                               request_kid_context=bytes.fromhex("57ab2e"),
                               is_request=False, oscore_option_override=b"")
        self.assertTrue(good.ok, good.note)
        self.assertFalse(empty.ok)


class TestPairwiseRoundTrip(unittest.TestCase):
    def setUp(self):
        self.ctx = G.PairwiseContext(bytes.fromhex("0102030405060708090a0b0c0d0e0f21"),
                                     bytes.fromhex("9e7ca92223786340"),
                                     sender_id=bytes.fromhex("01"),
                                     recipient_id=bytes.fromhex("00"))

    def _protect(self, nonce_piv, inner, key, request_kid=b"\x01", request_piv=b"\x65"):
        """Protect with `key`; the AAD always names the request kid / Partial IV."""
        aad = G.aad_oscore(request_kid, request_piv, b"", self.ctx.aead_alg)
        nonce = self.ctx.nonce(nonce_piv, request_kid)
        return G.aead_encrypt(key, nonce, inner.as_transport_independent(), aad)

    def test_request_and_response(self):
        inner = G.InnerMessage(G.CODE_GET, [(G.OPT_OBSERVE, b""),
                                            (G.OPT_URI_PATH, b"r")], b"")
        payload = self._protect(b"\x65", inner, self.ctx.sender_key)
        msg = G.CoapMessage(0, G.CODE_FETCH, 0xC98A, b"\x4a",
                            [(G.OPT_OBSERVE, b""), (9, b"\x09\x65\x01")], payload)
        result = G.verify_pairwise(msg, self.ctx, key=self.ctx.sender_key)
        self.assertTrue(result.ok, result.note)
        self.assertEqual(result.plaintext.code, G.CODE_GET)
        self.assertEqual(result.plaintext.opts(G.OPT_URI_PATH), [b"r"])

    def test_response_reuses_the_request_nonce(self):
        """RFC 8613 §5.2: a response without a Partial IV reuses the request's nonce, and
        ID_PIV is the Sender ID of the endpoint that generated that Partial IV."""
        inner = G.InnerMessage(G.CODE_SERVICE_UNAVAILABLE,
                               [(G.OPT_CONTENT_FORMAT, b"\x0c")], b"\xa0")
        payload = self._protect(b"\x65", inner, self.ctx.recipient_key)
        msg = G.CoapMessage(0, G.CODE_CHANGED, 0x5069, b"\x4a", [(9, b"")], payload)
        result = G.verify_pairwise(msg, self.ctx, request_kid=b"\x01",
                                   request_piv=b"\x65")
        self.assertTrue(result.ok, result.note)
        self.assertEqual(result.plaintext.code, G.CODE_SERVICE_UNAVAILABLE)

    def test_group_flag_is_refused(self):
        inner = G.InnerMessage(G.CODE_GET, [], b"")
        payload = self._protect(b"\x65", inner, self.ctx.sender_key)
        msg = G.CoapMessage(0, G.CODE_FETCH, 0, b"\x4a",
                            [(9, G.compress_oscore_option(b"\x65", None, b"\x01", True))],
                            payload)
        with self.assertRaises(G.VerifyError):
            G.verify_pairwise(msg, self.ctx, key=self.ctx.sender_key)

    def test_replay_window_is_never_consulted_by_the_verifier(self):
        """The verifier holds no replay state at all: MO-15 §9.3.1's replay exception is a
        property of the endpoint, not of the cryptography.  Verifying the same
        authenticated message twice therefore succeeds, which is what lets a second
        client accept the same 'ph_req'."""
        inner = G.InnerMessage(G.CODE_GET, [], b"")
        payload = self._protect(b"\x65", inner, self.ctx.sender_key)
        msg = G.CoapMessage(0, G.CODE_FETCH, 0, b"\x4a",
                            [(9, b"\x09\x65\x01")], payload)
        self.assertTrue(G.verify_pairwise(msg, self.ctx, key=self.ctx.sender_key).ok)
        self.assertTrue(G.verify_pairwise(msg, self.ctx, key=self.ctx.sender_key).ok)


# ---------------------------------------------------------------------------
# encodings
# ---------------------------------------------------------------------------

class TestCbor(unittest.TestCase):
    def test_deterministic_integer_encoding(self):
        self.assertEqual(G.cbor_encode(0), b"\x00")
        self.assertEqual(G.cbor_encode(23), b"\x17")
        self.assertEqual(G.cbor_encode(24), b"\x18\x18")
        self.assertEqual(G.cbor_encode(255), b"\x18\xff")
        self.assertEqual(G.cbor_encode(256), b"\x19\x01\x00")
        self.assertEqual(G.cbor_encode(-1), b"\x20")
        self.assertEqual(G.cbor_encode(-8), b"\x27")
        self.assertEqual(G.cbor_encode(501), b"\x19\x01\xf5")
        self.assertEqual(G.cbor_encode(-27), b"\x38\x1a")  # -1 - 26
        self.assertEqual(G.cbor_encode(-8), b"\x27")        # -1 - 7

    def test_map_keys_are_length_then_bytewise_sorted(self):
        """RFC 9052 §3.1: COSE maps use the deterministic ordering."""
        encoded = G.cbor_encode({-25: b"x", 1: 1, 10: 2})
        self.assertEqual(encoded[0] | 0x1F, 0xA0 | 0x1F)  # map of 3
        array, end = G.cbor_decode(encoded, 0)
        self.assertEqual(end, len(encoded))
        self.assertEqual(list(array.keys()), [1, 10, -25])

    def test_round_trip_and_canonicality(self):
        for value in (0, -1, 27, 501, -27, b"", b"\x00\x01", "", [], [1, [2], b"x"],
                      {1: 2, 3: b"y"}, None, True, False):
            with self.subTest(value=value):
                encoded = G.cbor_encode(value)
                decoded, end = G.cbor_decode(encoded, 0)
                self.assertEqual(end, len(encoded))
                self.assertEqual(decoded, value)
                self.assertTrue(G.cbor_is_canonical(encoded))

    def test_non_canonical_encoding_is_rejected(self):
        # 0x18 0x05 encodes 5 in a longer form than necessary (RFC 8949 §4.2.1).
        self.assertFalse(G.cbor_is_canonical(b"\x18\x05"))

    def test_duplicate_map_keys_are_rejected(self):
        with self.assertRaises(G.CborError):
            G.cbor_decode(b"\xa2\x01\x01\x01\x02", 0)

    def test_truncated_input_is_rejected(self):
        with self.assertRaises(G.CborError):
            G.cbor_decode(b"\x58\x10\x01", 0)


class TestCoap(unittest.TestCase):
    def test_header_layout(self):
        """RFC 7252 §3: Ver | T | TKL — the Token Length is the *low* nibble."""
        # Ver | T | TKL, with TKL in the low nibble: 0x55 is version 1,
        # Non-confirmable, with a 5-octet Token.
        msg = G.parse_coap(bytes.fromhex("550200c9") + bytes.fromhex("4a12345678")
                           + bytes.fromhex("6101"))
        self.assertEqual(msg.mtype, 1)   # Non-confirmable
        self.assertEqual(msg.code, 0x02)
        self.assertEqual(msg.mid, 0xC9)
        self.assertEqual(msg.token, bytes.fromhex("4a12345678"))
        self.assertEqual(msg.options, [(6, b"\x01")])
        self.assertEqual(msg.payload, b"")

    def test_payload_marker(self):
        msg = G.parse_coap(bytes.fromhex("510000c94a") + b"\xff" + b"body")
        self.assertEqual(msg.payload, b"body")
        self.assertEqual(msg.options, [])
        self.assertEqual(msg.token, b"\x4a")
        # Options followed by a Payload Marker.
        msg = G.parse_coap(bytes.fromhex("510000c94a") + bytes.fromhex("6101")
                           + b"\xff" + b"body")
        self.assertEqual(msg.options, [(6, b"\x01")])
        self.assertEqual(msg.payload, b"body")
        # A zero-length payload leaves the marker off (RFC 7252 §3).
        self.assertEqual(G.parse_coap(bytes.fromhex("510000c94a")).payload, b"")

    def test_option_serialisation_round_trip(self):
        options = [(6, b""), (9, b"\x09\x65\x01"), (11, b"r"), (11, b"s")]
        self.assertEqual(G.parse_options(G.serialize_options(options)), options)

    def test_token_length_bounds(self):
        """RFC 7252 §3.1: TKL values 9-15 are reserved."""
        with self.assertRaises(G.VerifyError):
            G.parse_coap(bytes.fromhex("590200c9") + bytes(16))
        with self.assertRaises(G.VerifyError):
            G.parse_coap(bytes.fromhex("510200c9"))  # TKL 1 but no token octet

    def test_reserved_option_nibble_is_rejected(self):
        with self.assertRaises(G.VerifyError):
            G.parse_coap(bytes.fromhex("510000c94a") + b"\xf0\x00")  # delta 15

    def test_transport_independent_encoding(self):
        """MO-15 §4.2.2: Code | options | 0xff | payload, with no header or Token."""
        raw = G.serialize_transport_independent(G.CODE_FETCH,
                                                [(G.OPT_OBSERVE, b"")], b"\xaa\xbb")
        self.assertEqual(raw[0], G.CODE_FETCH)
        code, options, payload = G.parse_transport_independent(raw)
        self.assertEqual(code, G.CODE_FETCH)
        self.assertEqual(options, [(G.OPT_OBSERVE, b"")])
        self.assertEqual(payload, b"\xaa\xbb")
        # An empty payload produces no Payload Marker.
        raw = G.serialize_transport_independent(G.CODE_CONTENT, [], b"")
        self.assertEqual(raw, bytes([G.CODE_CONTENT]))
        self.assertNotIn(b"\xff", raw)


class TestInformativeResponse(unittest.TestCase):
    def test_tp_info_shape(self):
        """MO-15 §4.2.1.1 Figure 3: [tpi_server, tpi_client, tpi_token]."""
        # authority is [host, ?port]; host is a tstr (DNS name) or a bstr (IP literal).
        value = [[-1, [4, b"\x7f\x00\x00\x01"]], [-1, [4, b"D", 61616]], b"\x7b"]
        decoded = G.decode_tp_info(value)
        self.assertEqual(decoded["server"]["scheme_id"], -1)
        self.assertEqual(decoded["server"]["authority"], [4, b"\x7f\x00\x00\x01"])
        self.assertEqual(decoded["client"]["authority"], [4, b"D", 61616])
        self.assertEqual(decoded["client"]["authority"][2], 61616)
        self.assertEqual(decoded["token"], b"\x7b")

    def test_malformed_tp_info_is_rejected(self):
        for value in ([], [[-1], [-1], b"\x7b"], [[-1, []], [-1, []], 0x7b]):
            with self.subTest(value=value):
                with self.assertRaises(G.VerifyError):
                    G.decode_tp_info(value)

    def test_key_names_match_the_draft(self):
        """MO-15 §11 Table 2."""
        self.assertEqual(G.IR_KEYS[0], "tp_info")
        self.assertEqual(G.IR_KEYS[1], "ph_req")
        self.assertEqual(G.IR_KEYS[2], "last_notif")
        self.assertEqual(G.IR_KEYS[5], "join_uri")
        self.assertEqual(G.IR_KEYS[6], "sec_gp")


# ---------------------------------------------------------------------------
# capture reading and end-to-end analysis
# ---------------------------------------------------------------------------

def build_pcap(frames):
    """A minimal little-endian pcap with BSD loopback link type (what tcpdump on lo0
    produces) holding the given UDP payloads."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 524288, 0))
    for index, (src, sport, dst, dport, payload) in enumerate(frames, start=1):
        ip = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), index,
                                   0, 64, 17, 0,
                                   bytes(int(p) for p in src.split(".")),
                                   bytes(int(p) for p in dst.split("."))))
        udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
        frame = b"\x02\x00\x00\x00" + bytes(ip) + udp
        out += struct.pack("<IIII", 1700000000, index, len(frame), len(frame)) + frame
    return bytes(out)


class TestCaptureReader(unittest.TestCase):
    def test_loopback_capture(self):
        payload = G.serialize_coap(G.CoapMessage(0, 0x01, 0x1234, b"\x4a", [], b"hi"))
        data = build_pcap([("127.0.0.1", 40000, "127.0.0.1", 5683, payload)])
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
            handle.write(data)
            path = handle.name
        try:
            packets = G.read_pcap(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["src"], "127.0.0.1")
        self.assertEqual(packets[0]["dport"], 5683)
        self.assertEqual(bytes.fromhex(packets[0]["payload"]), payload)
        self.assertEqual(G.parse_coap(bytes.fromhex(packets[0]["payload"])).token, b"\x4a")

    def test_ipv6_capture(self):
        ip6 = bytearray(struct.pack(">IHBB", 0x60000000, 8 + 4, 17, 64))
        ip6 += bytes.fromhex("20010db80000000000000000000000ab")
        ip6 += bytes.fromhex("ff35003020010db80000000000000023")
        udp = struct.pack(">HHHH", 5683, 61616, 8 + 4, 0) + b"\xde\xad\xbe\xef"
        data = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 524288, 0))
        frame = b"\x1e\x00\x00\x00" + bytes(ip6) + udp  # AF_INET6 loopback
        data += struct.pack("<IIII", 1700000000, 1, len(frame), len(frame)) + frame
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
            handle.write(bytes(data))
            path = handle.name
        try:
            packets = G.read_pcap(path)
        finally:
            os.unlink(path)
        self.assertEqual(packets[0]["src"], "2001:db8::ab")
        self.assertEqual(packets[0]["dst"], "ff35:30:2001:db8::23")
        self.assertEqual(packets[0]["dport"], 61616)
        self.assertEqual(bytes.fromhex(packets[0]["payload"]), b"\xde\xad\xbe\xef")

    def test_unrecognised_magic_is_refused(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
            handle.write(b"not a capture file at all, really")
            path = handle.name
        try:
            with self.assertRaises(G.VerifyError):
                G.read_pcap(path)
        finally:
            os.unlink(path)


class TestEndToEnd(unittest.TestCase):
    """The verifier run over the Section-10 capture, if both artifacts are present."""

    def setUp(self):
        if not os.path.exists(VECTOR_PATH):
            self.skipTest("docs/secure/section10-vector.json is not present")
        if not os.path.exists(PCAP_PATH):
            self.skipTest("evidence/section10/section10.pcap is not present")

    def test_every_observable_row_passes(self):
        vector = G.load_vector(VECTOR_PATH)
        analysis = G.Analysis(vector, G.read_pcap(PCAP_PATH))
        conf = analysis.run()
        self.assertEqual(conf.failed, [],
                         "failing rows: %s" % [(r, conf.rows[r][1]) for r in conf.failed])

    def test_two_registrations_one_phantom_request(self):
        vector = G.load_vector(VECTOR_PATH)
        analysis = G.Analysis(vector, G.read_pcap(PCAP_PATH))
        analysis.run()
        self.assertEqual(len(analysis.registrations), 2)
        firsts = [r.ir[1] for r in analysis.registrations if r.ir]
        self.assertEqual(len(set(firsts)), 1, "the two clients must share one 'ph_req'")

    def test_sequence_numbers(self):
        """MO-15 §10 with the corrected Partial IV numbering."""
        vector = G.load_vector(VECTOR_PATH)
        analysis = G.Analysis(vector, G.read_pcap(PCAP_PATH))
        analysis.run()
        base = next(r for r in analysis.registrations if r.phantom_osc)
        self.assertEqual(int.from_bytes(base.phantom_osc.piv, "big"), 501)
        self.assertEqual(int.from_bytes(base.phantom_osc.kid, "big"), 0x05)
        self.assertEqual(int.from_bytes(base.last_notif_osc.piv, "big"), 502)
        wire = [int.from_bytes(osc.piv, "big") for _, _, osc in analysis.notifications]
        self.assertEqual(wire[0], 503)
        self.assertEqual(wire, sorted(wire))
        self.assertEqual(len(set(wire)), len(wire))

    def _stored_baseline_run(self, values, initial_value):
        """Re-decide R9.10.1 over the Section-10 capture with the given allowed sets.

        `analysis.run()` populates the registrations, the stored INIT_NOTIF and the wire
        notifications; the row is then recomputed from scratch so that the row's outcome
        depends only on the two sets the vector declares.
        """
        vector = G.load_vector(VECTOR_PATH)
        analysis = G.Analysis(vector, G.read_pcap(PCAP_PATH))
        analysis.run()
        vector.values = [v.encode() for v in values]
        vector.initial_value = [v.encode() for v in initial_value]
        analysis.conf = G.Conformance()
        analysis.check_expected()
        return analysis.conf

    def test_stored_baseline_declared_only_as_initial_value_passes(self):
        """MO-15 §4.1 Step 6: the stored INIT_NOTIF carries the representation the server
        holds before it has transmitted anything, and the draft fixes no value for it.  A
        baseline declared in `scenario.initial_value` alone therefore satisfies R9.10.1 —
        this is the java-demo case, whose counter starts at 0 while its transmitted
        values start at 1."""
        conf = self._stored_baseline_run(["5678"], ["1234"])
        self.assertNotIn("R9.10.1", conf.failed)

    def test_stored_payload_in_neither_set_fails(self):
        """The acceptance is not unconditional: a stored payload that is neither a
        transmitted value nor the declared baseline is still a failure."""
        conf = self._stored_baseline_run(["5678"], ["9999"])
        self.assertIn("R9.10.1", conf.failed)
        self.assertIn("9999", conf.rows["R9.10.1"][1])

    def test_vector_declares_only_public_fixtures(self):
        """No value in the vector may look like a real secret: they are the shipped
        profile fixtures, and the same values must appear in the profile files."""
        root = os.path.dirname(os.path.abspath(__file__))
        with open(VECTOR_PATH) as handle:
            import json
            vector = json.load(handle)
        for name in ("master_secret", "master_salt"):
            value = vector["group"][name]
            self.assertEqual(len(value), 32 if name == "master_secret" else 16)
        for client in vector["clients"]:
            path = os.path.join(root, "..", "docs", "secure", "examples", "section10",
                                "%s.conf" % client["label"].lower())
            if not os.path.exists(path):
                continue
            with open(path) as handle:
                text = handle.read()
            self.assertIn(client["pairwise"]["master_secret"], text)
            self.assertIn(client["group_sender"]["private_key_seed"], text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
