#ifndef SEC_STATE_H
#define SEC_STATE_H

#include <coap3/coap.h>
#include <stdint.h>

/* MO-15 §4.3: a stored notification with no Inner Max-Age option is stale
 * after 60 seconds.  Overridable per run with the server's -M. */
#define SEC_NOTIF_DEFAULT_MAX_AGE 60

typedef struct {
    uint8_t kid[8]; size_t kid_len;
    uint8_t piv[5]; size_t piv_len;
    uint8_t kid_ctx[16]; size_t kid_ctx_len;
} sec_tuple_t;

typedef struct {
    uint8_t  token[8];  size_t token_len;          /* T (MO-15 §4.1 step 2) */
    unsigned observers;                            /* observer counter (MO-15 §4.2) */
    uint8_t  ph_req[256];  size_t ph_req_len;      /* protected phantom, §4.2.2 form (§9.2.2) */
    sec_tuple_t tuple;                             /* kid, piv, kid_context bytes from ph_req's option */
    uint32_t observe;                              /* last outer Observe used (INIT_NOTIF = 1) */
    uint64_t notifs_sent;                          /* wire notifications (for -n) */
    uint8_t  latest[256];  size_t latest_len;      /* stored latest protected notification, §4.2.2 form */
    uint64_t latest_piv;                           /* its PIV (diagnostics, tests) */
    int      latest_is_init;                       /* 1 while it is INIT_NOTIF (§4.1 step 6) */
    coap_tick_t latest_created;  unsigned latest_max_age;   /* refresh (§4.3) */
    enum { GOBS_NONE, GOBS_ACTIVE, GOBS_CANCELLED } state;  /* cancellation state: never CANCELLED in this version */
} sec_srv_gobs_t;

typedef struct {
    char     grp_addr[64]; uint16_t grp_port;     /* multicast endpoint (tpi_client) */
    char     srv_addr[64]; uint16_t srv_port;     /* tpi_server, for the §5.2 step 1 source check */
    uint8_t  token[8]; size_t token_len;          /* T */
    sec_tuple_t tuple;  int tuple_valid;          /* verified phantom identifiers (§9.3.1) */
    int      rn_valid;  uint64_t rn;              /* Response Number: notification replay state,
                                                     independent of the Recipient replay window */
    uint32_t last_observe; char last_value[64];   /* latest accepted Observe / representation */
    unsigned delivered, rejected;                 /* counters for tests and logs */
} sec_cli_gobs_t;

struct sec_grp_s;
void sec_srv_gobs_start(sec_srv_gobs_t *g, struct sec_grp_s *grp, const char *uri_path, const uint8_t *T, size_t tkl);
void sec_cli_gobs_clear(sec_cli_gobs_t *g);
int sec_cli_gobs_bind(sec_cli_gobs_t *g, const sec_tuple_t *tuple,
                      const uint8_t *token, size_t token_len,
                      const char *srv_host, uint16_t srv_port,
                      const char *grp_host, uint16_t grp_port);
int sec_cli_accept(sec_cli_gobs_t *g, uint64_t piv);

/* MO-15 §4.1 step 6 and §4.3.  `ti` are the transport-independent
 * bytes of the notification that went on the wire (MO-15 §4.2.2 form); they
 * become the stored latest notification verbatim, which also retires
 * INIT_NOTIF (`latest_is_init` cleared) and restarts the Max-Age clock at
 * `now`.  Returns 0, or -1 when the bytes do not fit `latest[]`. */
int sec_srv_latest_replace(sec_srv_gobs_t *g, const uint8_t *ti, size_t ti_len,
                           uint64_t piv, unsigned max_age, coap_tick_t now);
/* 1 once the stored latest notification has reached an age greater than its
 * maximum age (§4.3), 0 otherwise (including when nothing is stored). */
int sec_srv_refresh_due(const sec_srv_gobs_t *g, coap_tick_t now);

#endif
