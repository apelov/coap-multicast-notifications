#include "sec_group.h"
#include "sec_ti.h"
#include <coap3/coap_internal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Interop only. Verify with the Java peer's empty OSCORE_option in
 * external_aad, using the pinned fork's crypto primitives (GO-28 §7.2).
 * The Recipient Context is read but its replay state is never touched. */
static coap_pdu_t *verify_empty_phreq_aad(sec_grp_t *grp, coap_pdu_t *outer) {
    coap_opt_iterator_t oi;
    coap_opt_t *opt = coap_check_option(outer, COAP_OPTION_OSCORE, &oi);
    cose_encrypt0_t cose[1];
    oscore_recipient_ctx_t *rc = grp->ctx->p_osc_ctx->recipient_chain;
    oscore_ctx_t *ctx = grp->ctx->p_osc_ctx;
    const uint8_t *payload;
    size_t payload_len;
    uint8_t e_aad[600], aad[700], sig_struct[1024], sig[64], stream[64];
    uint8_t nonce_buf[13], plain[512], udp[4 + 8 + sizeof(plain)];
    coap_bin_const_t e_aadb, aadb, nonce, signed_text;
    coap_binary_t signature = { sizeof(sig), sig };
    coap_pdu_t *inner = NULL;
    size_t e_len, sig_len, ct_len;
    int plain_len;
    if (!opt || !rc || !rc->rem_cred || !rc->recipient_key ||
        !coap_get_data(outer, &payload_len, &payload) ||
        payload_len <= sizeof(sig) + 8 || payload_len > sizeof(plain) + sizeof(sig)) return NULL;
    cose_encrypt0_init(cose);
    if (!oscore_decode_option_value(coap_opt_value(opt), coap_opt_length(opt), cose) ||
        !cose->group_flag || rc->mode != OSCORE_MODE_GROUP ||
        cose->key_id.length != rc->recipient_id->length ||
        memcmp(cose->key_id.s, rc->recipient_id->s, cose->key_id.length) != 0) return NULL;
    cose_encrypt0_set_alg(cose, ctx->alg_group_enc);
    e_len = oscore_prepare_e_aad(ctx, cose, coap_opt_value(opt), 0,
                                  rc->rem_cred, rc->mode, e_aad, sizeof(e_aad));
    if (!e_len || e_len > sizeof(e_aad)) return NULL;
    e_aadb.s = e_aad; e_aadb.length = e_len;
    cose_encrypt0_set_external_aad(cose, &e_aadb);
    aadb.s = aad;
    aadb.length = oscore_prepare_aad(e_aad, e_len, aad, sizeof(aad));
    if (!aadb.length || aadb.length > sizeof(aad)) return NULL;
    cose_encrypt0_set_aad(cose, &aadb);
    oscore_generate_nonce(cose, ctx, nonce_buf, sizeof(nonce_buf));
    nonce.s = nonce_buf; nonce.length = sizeof(nonce_buf);
    cose_encrypt0_set_nonce(cose, &nonce);
    ct_len = payload_len - sizeof(sig);
    oscore_derive_keystream(ctx, cose, 1, rc->recipient_id, &cose->kid_context,
                            sizeof(stream), stream, sizeof(stream));
    for (size_t i = 0; i < sizeof(sig); i++) sig[i] = payload[ct_len + i] ^ stream[i];
    sig_len = oscore_prepare_sig_structure(sig_struct, sizeof(sig_struct),
                                           e_aad, e_len, payload, ct_len);
    signed_text.s = sig_struct; signed_text.length = sig_len;
    if (!sig_len || sig_len > sizeof(sig_struct) ||
        !coap_crypto_hash_verify(rc->rem_cred->sign_hash, &signature, &signed_text, rc->rem_cred)) return NULL;
    cose_encrypt0_set_key(cose, rc->recipient_key);
    cose_encrypt0_set_ciphertext(cose, (uint8_t *)payload, ct_len);
    plain_len = cose_encrypt0_decrypt(cose, plain, sizeof(plain));
    if (plain_len < 1 || (size_t)plain_len > sizeof(plain)) return NULL;
    coap_bin_const_t tok = coap_pdu_get_token(outer);
    if (tok.length > 8) return NULL;
    udp[0] = 0x50 | (uint8_t)tok.length;
    udp[1] = plain[0]; udp[2] = udp[3] = 0;
    memcpy(udp + 4, tok.s, tok.length);
    memcpy(udp + 4 + tok.length, plain + 1, (size_t)plain_len - 1);
    inner = coap_pdu_init(0, 0, 0, sizeof(udp));
    if (!inner || !coap_pdu_parse(COAP_PROTO_UDP, udp,
                                   4 + tok.length + (size_t)plain_len - 1, inner)) {
        coap_delete_pdu(inner);
        return NULL;
    }
    return inner;
}

int sec_phantom_protect(sec_grp_t *grp, const char *uri_path, const uint8_t *T, size_t tkl, uint8_t *ph_req, size_t *ph_len, sec_tuple_t *tuple) {
    if (!grp || !grp->ctx || !grp->ctx->p_osc_ctx || !uri_path || !*uri_path ||
        !T || tkl > 8 || !ph_req || !ph_len || !tuple) return 0;
    coap_pdu_t *plain = coap_pdu_init(COAP_MESSAGE_NON, COAP_REQUEST_CODE_GET, 0, 256);
    if (!plain) return 0;
    /* MO-15 §4.1: the request processed locally is GET/Observe 0/Uri-Path. */
    if (!coap_add_token(plain, tkl, T) ||
        !coap_add_option(plain, COAP_OPTION_OBSERVE, 0, NULL) ||
        !coap_add_option(plain, COAP_OPTION_URI_PATH, strlen(uri_path), (const uint8_t *)uri_path)) {
        coap_delete_pdu(plain);
        return 0;
    }

    coap_session_t *sess = calloc(1, sizeof(coap_session_t));
    if (!sess) {
        coap_delete_pdu(plain);
        return 0;
    }
    sess->context = grp->ctx;
    sess->proto = COAP_PROTO_UDP;
    sess->type = COAP_SESSION_TYPE_CLIENT;
    sess->recipient_ctx = grp->ctx->p_osc_ctx->recipient_chain;

    /* The patched fork uses this Sender Context in group mode (MO-15 §9.2.1,
     * GO-28 §7.1); its finalized OSCORE option is bound into external_aad. */
    coap_pdu_t *osc = coap_oscore_new_pdu_encrypted(sess, plain, NULL, OSCORE_SEND_PARTIAL_IV);
    coap_delete_pdu(plain);
    coap_lock_lock(goto cleanup_session);
    oscore_delete_server_associations(sess);
    coap_lock_unlock();
cleanup_session:
    free(sess);

    if (!osc) return 0;

    coap_opt_iterator_t oi;
    coap_opt_t *opt = coap_check_option(osc, COAP_OPTION_OSCORE, &oi);
    size_t payload_len = 0;
    const uint8_t *payload = NULL;
    if (coap_pdu_get_code(osc) != COAP_REQUEST_CODE_FETCH ||
        !coap_check_option(osc, COAP_OPTION_OBSERVE, &oi) || !opt ||
        !coap_get_data(osc, &payload_len, &payload) || payload_len <= 64 ||
        !sec_tuple_from_option(coap_opt_value(opt), coap_opt_length(opt), tuple)) {
        coap_delete_pdu(osc);
        return 0;
    }

    size_t req_len = sec_ti_export(osc, ph_req, *ph_len);
    coap_delete_pdu(osc);
    if (!req_len) return 0;
    *ph_len = req_len;
    return 1;
}

int sec_phantom_verify(sec_grp_t *grp, const uint8_t *ph_req, size_t ph_len, const uint8_t *T, size_t tkl, const char *expect_path, unsigned compat, sec_tuple_t *out) {
    if (!grp || !grp->ctx || !grp->ctx->p_osc_ctx || !ph_req || !ph_len || !T || !tkl || tkl > 8 || !expect_path || !out) return 0;
    memset(out, 0, sizeof(*out));
    coap_pdu_t *pdu = NULL;
    int ret = sec_ti_import(ph_req, ph_len, T, tkl, 1, compat & 1u, &pdu);
    if (!pdu || ret <= 0) return 0;

    coap_session_t *sess = calloc(1, sizeof(coap_session_t));
    if (!sess) {
        coap_delete_pdu(pdu);
        return 0;
    }
    sess->context = grp->ctx;
    sess->proto = COAP_PROTO_UDP;
    sess->type = COAP_SESSION_TYPE_SERVER;
    sess->recipient_ctx = grp->ctx->p_osc_ctx->recipient_chain;

    coap_pdu_t *dec = NULL;
    int ok = 0;
    if (compat & 2u) {
        dec = verify_empty_phreq_aad(grp, pdu);
    } else {
        coap_lock_lock(goto cleanup_session);
        dec = coap_oscore_decrypt_pdu_ext(sess, pdu, COAP_OSCORE_DECRYPT_NO_REPLAY);
        coap_lock_unlock();
    }

    if (dec && coap_pdu_get_code(dec) == COAP_REQUEST_CODE_GET) {
        coap_opt_iterator_t oi;
        coap_opt_t *opt = coap_check_option(dec, COAP_OPTION_URI_PATH, &oi);
        coap_opt_t *obs = coap_check_option(dec, COAP_OPTION_OBSERVE, &oi);
        uint32_t obs_val = obs ? coap_decode_var_bytes(coap_opt_value(obs), coap_opt_length(obs)) : 1;
        size_t data_len;
        const uint8_t *data;
        unsigned paths = 0, observes = 0, other = 0;
        coap_option_iterator_init(dec, &oi, COAP_OPT_ALL);
        coap_opt_t *item;
        while ((item = coap_option_next(&oi))) {
            (void)item;
            if (oi.number == COAP_OPTION_URI_PATH) paths++;
            else if (oi.number == COAP_OPTION_OBSERVE) observes++;
            else other++;
        }
        if (paths == 1 && observes == 1 && other == 0 &&
            !coap_get_data(dec, &data_len, &data) &&
            opt && coap_opt_length(opt) == strlen(expect_path) &&
            memcmp(coap_opt_value(opt), expect_path, strlen(expect_path)) == 0 &&
            obs && obs_val == 0) {

            // Extract the tuple from the original PDU's OSCORE option
            coap_opt_t *oscore_opt = coap_check_option(pdu, COAP_OPTION_OSCORE, &oi);
            if (oscore_opt && sec_tuple_from_option(coap_opt_value(oscore_opt), coap_opt_length(oscore_opt), out)) {
                ok = 1;
            }
        }
    }

cleanup_session:
    coap_delete_pdu(dec);
    free(sess);
    coap_delete_pdu(pdu);
    return ok;
}

static const coap_bin_const_t *sec_cred_bytes(const coap_crypto_cred_t *c) {
    if (!c) return NULL;
    return c->cred_type == OSCORE_AUTH_CRED_CCS ? c->auth_cred : c->pub_der;
}


static size_t pdu_bytes(coap_pdu_t *pdu, const uint8_t **p) {
    if (!coap_pdu_encode_header(pdu, COAP_PROTO_UDP)) return 0;
    *p = pdu->token - pdu->hdr_size;
    return pdu->hdr_size + pdu->used_size;
}

size_t sec_build_e_aad(oscore_ctx_t *ctx, const sec_tuple_t *req, const uint8_t *opt, size_t optlen, const coap_crypto_cred_t *sender, uint8_t *out, size_t max) {
    uint8_t *p = out;
    size_t rem = max, len = 0;
    if (!ctx || !req || !sender || !out) return 0;

#define PUT_ALG(a) ((a) ? oscore_cbor_put_number(&p, &rem, (a)) : oscore_cbor_put_nil(&p, &rem))
    len += oscore_cbor_put_array(&p, &rem, 9);
    len += oscore_cbor_put_unsigned(&p, &rem, 1);
    len += oscore_cbor_put_array(&p, &rem, 4);
    len += PUT_ALG(ctx->aead_alg);
    len += PUT_ALG(ctx->alg_group_enc);
    len += PUT_ALG(ctx->alg_signature);
    len += PUT_ALG(ctx->alg_pairwise_key_agreement);
#undef PUT_ALG
    len += oscore_cbor_put_bytes(&p, &rem, req->kid, req->kid_len);
    len += oscore_cbor_put_bytes(&p, &rem, req->piv, req->piv_len);
    len += oscore_cbor_put_bytes(&p, &rem, NULL, 0); /* options: no I options */
    len += oscore_cbor_put_bytes(&p, &rem, req->kid_ctx, req->kid_ctx_len);
    len += oscore_cbor_put_bytes(&p, &rem, opt, optlen);

    const coap_bin_const_t *sc = sec_cred_bytes(sender);
    len += oscore_cbor_put_bytes(&p, &rem, sc->s, sc->length);

    if (ctx->gm_cred) {
        const coap_bin_const_t *gc = sec_cred_bytes(ctx->gm_cred);
        len += oscore_cbor_put_bytes(&p, &rem, gc->s, gc->length);
    } else {
        len += oscore_cbor_put_nil(&p, &rem);
    }
    return len;
}

int sec_notif_protect(sec_grp_t *grp, const sec_tuple_t *req, const uint8_t *T, size_t tkl, uint32_t observe, const uint8_t *val, size_t vallen, unsigned max_age, coap_mid_t mid, uint8_t *udp, size_t *udp_len, uint8_t *ti, size_t *ti_len, uint64_t *piv) {
    if (!grp || !grp->ctx || !grp->ctx->p_osc_ctx || !req || !T || !udp || !udp_len || !ti || !ti_len || !piv) return 0;
    oscore_ctx_t *osc = grp->ctx->p_osc_ctx;
    oscore_sender_ctx_t *snd = osc->sender_context;
    if (!snd || !snd->group_mode) return 0;

    cose_encrypt0_t cose[1];
    cose_sign1_t sign[1];
    uint8_t piv_buf[8], aad[700], sig_struct[1024], keystream[64], pt[256], ob[4];
    uint8_t nonce_buf[13], e_aad_buf[600], opt_buf[256], payload_buf[512];
    coap_bin_const_t piv_bin, nonce, e_aad, aadb;
    size_t pt_len, ct_len, sig_len, i;
    const size_t sig_size = 64;
    coap_pdu_t *inner, *pdu;
    const uint8_t *udp_bytes;

    cose_encrypt0_init(cose);
    cose_sign1_init(sign);
    cose_encrypt0_set_alg(cose, osc->alg_group_enc);

    size_t p_len = coap_encode_var_safe(piv_buf, sizeof(piv_buf), snd->seq);
    if (snd->seq == 0) {
        piv_buf[0] = 0;
        p_len = 1;
    }
    piv_bin.s = piv_buf;
    piv_bin.length = p_len;
    *piv = snd->seq;

    cose_encrypt0_set_partial_iv(cose, &piv_bin);
    cose_encrypt0_set_key_id(cose, snd->sender_id);
    oscore_generate_nonce(cose, osc, nonce_buf, 13);
    if (!oscore_increment_sender_seq(osc)) return 0;

    nonce.s = nonce_buf;
    nonce.length = 13;
    cose_encrypt0_set_nonce(cose, &nonce);

    size_t opt_len = oscore_encode_option_value(opt_buf, sizeof(opt_buf), cose, 1, 0);
    size_t ea_len = sec_build_e_aad(osc, req, opt_buf, opt_len, snd->sender_cred, e_aad_buf, sizeof(e_aad_buf));
    if (!ea_len) return 0;

    e_aad.s = e_aad_buf;
    e_aad.length = ea_len;
    cose_encrypt0_set_external_aad(cose, &e_aad);
    aadb.length = oscore_prepare_aad(e_aad_buf, ea_len, aad, sizeof(aad));
    aadb.s = aad;
    cose_encrypt0_set_aad(cose, &aadb);
    cose_encrypt0_set_key(cose, snd->sender_key);

    /* plaintext: 2.05 | inner Observe | Content-Format | 0xff | payload
     *
     * The Content-Format of the representation is carried like the Java demo does
     * (text/plain, 0), so that the representation a client decrypts describes itself. The
     * inner Observe stays empty: RFC 8613 §4.1.3.5.2 requires it for notifications, and the
     * sequence number is kept in the outer Observe option. */
    inner = coap_pdu_init(COAP_MESSAGE_NON, COAP_RESPONSE_CODE(205), 0, 256);
    coap_add_option(inner, COAP_OPTION_OBSERVE, 0, NULL);
    /* Content-Format text/plain (0) is the default and encodes as a zero-length value */
    coap_add_option(inner, COAP_OPTION_CONTENT_FORMAT, 0, NULL);
    coap_add_data(inner, vallen, val);
    pt_len = sec_ti_export(inner, pt, sizeof(pt));
    coap_delete_pdu(inner);
    if (!pt_len) return 0;

    cose_encrypt0_set_plaintext(cose, pt, pt_len);
    ct_len = cose_encrypt0_encrypt(cose, payload_buf, sizeof(payload_buf));
    if ((int)ct_len <= 0) return 0;

    oscore_populate_sign(sign, osc, snd->sender_cred, snd->my_private_key);
    sig_len = oscore_prepare_sig_structure(sig_struct, sizeof(sig_struct), e_aad_buf, ea_len, payload_buf, ct_len);
    cose_sign1_set_signature(sign, payload_buf + ct_len, sig_size);
    cose_sign1_set_ciphertext(sign, sig_struct, sig_len);
    if (cose_sign1_sign(sign) != (int)sig_size) return 0;

    oscore_derive_keystream(osc, cose, 0, snd->sender_id, osc->id_context, sig_size, keystream, sig_size);
    for (i = 0; i < sig_size; i++) payload_buf[ct_len + i] ^= keystream[i];
    size_t final_payload_len = ct_len + sig_size;

    pdu = coap_pdu_init(COAP_MESSAGE_NON, COAP_RESPONSE_CODE(205), mid, 512);
    coap_add_token(pdu, tkl, T);
    coap_add_option(pdu, COAP_OPTION_OBSERVE, coap_encode_var_safe(ob, sizeof(ob), observe), ob);
    coap_add_option(pdu, COAP_OPTION_OSCORE, opt_len, opt_buf);
    /* RFC 8613: OSCORE-protected responses with outer code 2.05 (hence using Observe)
     * MUST include an Outer Max-Age Option with value 0 to prevent proxies from
     * caching the response to no avail. INIT_NOTIF (observe == 0) is never sent on
     * the wire, so it does not need this option. */
    if (observe != 0) {
        coap_add_option(pdu, COAP_OPTION_MAXAGE, 0, NULL);
    }
    coap_add_data(pdu, final_payload_len, payload_buf);

    *udp_len = pdu_bytes(pdu, &udp_bytes);
    if (*udp_len > 1024) { coap_delete_pdu(pdu); return 0; }
    memcpy(udp, udp_bytes, *udp_len);
    *ti_len = sec_ti_export(pdu, ti, 1024);
    coap_delete_pdu(pdu);
    return *ti_len > 0;
}

int sec_notif_verify(sec_grp_t *grp, const sec_tuple_t *req, coap_pdu_t *pdu, unsigned compat, uint64_t *piv, uint8_t *pt, size_t *ptlen) {
    if (!grp || !grp->ctx || !grp->ctx->p_osc_ctx || !req || !pdu || !piv || !pt || !ptlen) return 0;

    coap_bin_const_t rkid = { req->kid_len, req->kid };
    coap_bin_const_t rpiv = { req->piv_len, req->piv };
    coap_bin_const_t rkctx = { req->kid_ctx_len, req->kid_ctx };
    coap_opt_iterator_t oi;
    coap_opt_t *opt = coap_check_option(pdu, COAP_OPTION_OSCORE, &oi);
    cose_encrypt0_t cose[1];
    oscore_recipient_ctx_t *rcp = NULL;
    oscore_ctx_t *osc;
    coap_session_t *sess = calloc(1, sizeof(coap_session_t));
    if (!sess) return 0;
    sess->context = grp->ctx;
    sess->proto = COAP_PROTO_UDP;
    sess->type = COAP_SESSION_TYPE_CLIENT;
    sess->recipient_ctx = grp->ctx->p_osc_ctx->recipient_chain;

    uint8_t e_aad[600], aad[700], sig_struct[1024], sig[64], keystream[64], nonce_buf[13];
    coap_bin_const_t e_aadb, aadb, nonce, skid, mpiv;
    const uint8_t *data;
    size_t e_aad_len, ct_len, sig_len, i, len;
    int n, ok = 0;

    *ptlen = 0;
    cose_encrypt0_init(cose);
    if (!opt || !oscore_decode_option_value(coap_opt_value(opt), coap_opt_length(opt), cose) || !cose->group_flag)
        goto out;

    skid = cose->key_id.s ? cose->key_id : rkid;
    mpiv = cose->partial_iv;

    /* GO-28 §7.4 sender binding: the notification's kid MUST equal the
     * Tuple's kid.  Without this gate a different valid group sender
     * whose Recipient Context is configured could pass cryptographic
     * lookup by reusing the phantom Tuple as request AAD. */
    if (skid.length != rkid.length || memcmp(skid.s, rkid.s, rkid.length) != 0)
        goto out;

    osc = oscore_find_context(sess, skid, &rkctx, NULL, &rcp);
    if (!osc || !rcp || rcp->mode != OSCORE_MODE_GROUP) goto out;

    cose_encrypt0_set_alg(cose, osc->alg_group_enc);
    cose_encrypt0_set_key_id(cose, mpiv.length ? &skid : &rkid);
    cose_encrypt0_set_partial_iv(cose, mpiv.length ? &mpiv : &rpiv);
    oscore_generate_nonce(cose, osc, nonce_buf, 13);
    nonce.s = nonce_buf;
    nonce.length = 13;
    cose_encrypt0_set_nonce(cose, &nonce);

    e_aad_len = sec_build_e_aad(osc, req, coap_opt_value(opt), coap_opt_length(opt), rcp->rem_cred, e_aad, sizeof(e_aad));
    e_aadb.s = e_aad; e_aadb.length = e_aad_len;
    cose_encrypt0_set_external_aad(cose, &e_aadb);

    aadb.length = oscore_prepare_aad(e_aad, e_aad_len, aad, sizeof(aad));
    aadb.s = aad;
    cose_encrypt0_set_aad(cose, &aadb);

    if (!coap_get_data(pdu, &len, &data) || len <= 64 + 8) goto out;
    ct_len = len - 64;

    cose_encrypt0_set_partial_iv(cose, mpiv.length ? &mpiv : &rpiv);
    oscore_derive_keystream(osc, cose, 0, mpiv.length ? &skid : &rkid, osc->id_context, 64, keystream, 64);

    for (i = 0; i < 64; i++) sig[i] = data[ct_len + i] ^ keystream[i];

    sig_len = oscore_prepare_sig_structure(sig_struct, sizeof(sig_struct), e_aad, e_aad_len, data, ct_len);

    coap_bin_const_t signed_text = { sig_len, sig_struct };
    coap_binary_t signature = { 64, sig };
    if (!coap_crypto_hash_verify(rcp->rem_cred->sign_hash, &signature, &signed_text, rcp->rem_cred)) goto out;

    cose_encrypt0_set_key(cose, rcp->recipient_key);
    cose_encrypt0_set_ciphertext(cose, (uint8_t *)data, ct_len);
    n = cose_encrypt0_decrypt(cose, pt, 256);
    if (n > 0) {
        *ptlen = n;
        ok = 1;
        uint64_t v = 0;
        for (i=0; i<mpiv.length; i++) v = (v << 8) | mpiv.s[i];
        *piv = v;
    }

out:
    free(sess);
    return ok;
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int sec_mcast_send(coap_context_t *uc_ctx, const char *grp, uint16_t port, const uint8_t *udp, size_t len) {
    if (!uc_ctx || !uc_ctx->endpoint || !grp || !udp || !len || !port) return 0;
    int fd = uc_ctx->endpoint->sock.fd;
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    if (inet_pton(AF_INET, grp, &to.sin_addr) != 1 ||
        !IN_MULTICAST(ntohl(to.sin_addr.s_addr))) return 0;

    /* MO-15 §4.3 / design §6: use the informative-response socket's
     * concrete address as the outgoing interface, preserving its port. */
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
        perror("sec_mcast_send: getsockname");
        return 0;
    }
    if (local.sin_family != AF_INET || !local.sin_port ||
        local.sin_addr.s_addr == htonl(INADDR_ANY)) return 0;
    unsigned char loop = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                   &local.sin_addr, sizeof(local.sin_addr)) < 0 ||
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        perror("sec_mcast_send: multicast configuration");
        return 0;
    }

    ssize_t sent = sendto(fd, udp, len, 0, (struct sockaddr *)&to, sizeof(to));
    if (sent < 0) perror("sec_mcast_send: sendto");
    return sent == (ssize_t)len;
}
