// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL common provider capabilities.
 *
 * ToDo: Interop testing.
 */

#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <string.h>

/* For TLS1_VERSION etc */
#include <openssl/params.h>
#include <openssl/ssl.h>

// internal, but useful OSSL define:
#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

// enables DTLS1.3 testing even before available in openssl master:
#if !defined(DTLS1_3_VERSION)
#define DTLS1_3_VERSION 0xFEFC
#endif

#include "oqs_prov.h"

typedef struct oqs_group_constants_st {
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;            /* Always set */
} OQS_GROUP_CONSTANTS;

static OQS_GROUP_CONSTANTS oqs_group_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
    ///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_START
   { 512, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },

   { 0x2F4B, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 0x2FB6, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65056, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 513, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },

   { 0x2F4C, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 0x2FB7, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65057, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 0x11ec, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 0x11eb, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 514, 256, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },

   { 0x2F4D, 256, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 0x11ED, 256, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65058, 256, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65040, 128, -1, 0, -1, 0, 1 },

   { 65041, 128, -1, 0, -1, 0, 1 },
   { 65042, 128, -1, 0, -1, 0, 1 },
   { 65043, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },

   { 65044, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65045, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65048, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },

   { 65049, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65050, 128, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65051, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },

   { 65052, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65053, 192, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
   { 65054, 256, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },

   { 65055, 256, TLS1_3_VERSION, 0, DTLS1_3_VERSION, 0, 1 },
///// OQS_TEMPLATE_FRAGMENT_GROUP_ASSIGNMENTS_END
};

// Adds entries for tlsname, `ecx`_tlsname, `ecbp`_tlsname and `ecp`_tlsname
#define OQS_GROUP_ENTRY(tlsname, realname, algorithm, idx)                     \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, #tlsname,       \
                               sizeof(#tlsname)),                              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,    \
                                   #realname, sizeof(#realname)),              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, #algorithm,  \
                                   sizeof(#algorithm)),                        \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                      \
                            (unsigned int *)&oqs_group_list[idx].group_id),    \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,           \
                            (unsigned int *)&oqs_group_list[idx].secbits),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                  \
                           (unsigned int *)&oqs_group_list[idx].mintls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                  \
                           (unsigned int *)&oqs_group_list[idx].maxtls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                 \
                           (unsigned int *)&oqs_group_list[idx].mindtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                 \
                           (unsigned int *)&oqs_group_list[idx].maxdtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                   \
                           (unsigned int *)&oqs_group_list[idx].is_kem),       \
            OSSL_PARAM_END                                                     \
    }

static const OSSL_PARAM oqs_param_group_list[][11] = {
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_START

#ifdef OQS_ENABLE_KEM_ml_kem_512
    OQS_GROUP_ENTRY(mlkem512, mlkem512, mlkem512, 0),

    OQS_GROUP_ENTRY(p256_mlkem512, p256_mlkem512, p256_mlkem512, 1),
    OQS_GROUP_ENTRY(x25519_mlkem512, x25519_mlkem512, x25519_mlkem512, 2),
    OQS_GROUP_ENTRY(bp256_mlkem512, bp256_mlkem512, bp256_mlkem512, 3),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
    OQS_GROUP_ENTRY(mlkem768, mlkem768, mlkem768, 4),

    OQS_GROUP_ENTRY(p384_mlkem768, p384_mlkem768, p384_mlkem768, 5),
    OQS_GROUP_ENTRY(x448_mlkem768, x448_mlkem768, x448_mlkem768, 6),
    OQS_GROUP_ENTRY(bp384_mlkem768, bp384_mlkem768, bp384_mlkem768, 7),
    OQS_GROUP_ENTRY(X25519MLKEM768, X25519MLKEM768, X25519MLKEM768, 8),
    OQS_GROUP_ENTRY(SecP256r1MLKEM768, SecP256r1MLKEM768, SecP256r1MLKEM768, 9),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
    OQS_GROUP_ENTRY(mlkem1024, mlkem1024, mlkem1024, 10),

    OQS_GROUP_ENTRY(p521_mlkem1024, p521_mlkem1024, p521_mlkem1024, 11),
    OQS_GROUP_ENTRY(SecP384r1MLKEM1024, SecP384r1MLKEM1024, SecP384r1MLKEM1024, 12),
    OQS_GROUP_ENTRY(bp512_mlkem1024, bp512_mlkem1024, bp512_mlkem1024, 13),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    OQS_GROUP_ENTRY(bikel1, bikel1, bikel1, 14),

    OQS_GROUP_ENTRY(p256_bikel1, p256_bikel1, p256_bikel1, 15),
    OQS_GROUP_ENTRY(x25519_bikel1, x25519_bikel1, x25519_bikel1, 16),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    OQS_GROUP_ENTRY(bikel3, bikel3, bikel3, 17),

    OQS_GROUP_ENTRY(p384_bikel3, p384_bikel3, p384_bikel3, 18),
    OQS_GROUP_ENTRY(x448_bikel3, x448_bikel3, x448_bikel3, 19),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    OQS_GROUP_ENTRY(hqc128, hqc128, hqc128, 20),

    OQS_GROUP_ENTRY(p256_hqc128, p256_hqc128, p256_hqc128, 21),
    OQS_GROUP_ENTRY(x25519_hqc128, x25519_hqc128, x25519_hqc128, 22),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    OQS_GROUP_ENTRY(hqc192, hqc192, hqc192, 23),

    OQS_GROUP_ENTRY(p384_hqc192, p384_hqc192, p384_hqc192, 24),
    OQS_GROUP_ENTRY(x448_hqc192, x448_hqc192, x448_hqc192, 25),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    OQS_GROUP_ENTRY(hqc256, hqc256, hqc256, 26),

    OQS_GROUP_ENTRY(p521_hqc256, p521_hqc256, p521_hqc256, 27),
#endif
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

typedef struct oqs_sigalg_constants_st {
    unsigned int code_point; /* Code point */
    unsigned int secbits;    /* Bits of security */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
} OQS_SIGALG_CONSTANTS;

static OQS_SIGALG_CONSTANTS oqs_sigalg_list[] = {
    // ad-hoc assignments - take from OQS generate data structures
    ///// OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_START
    { 0x0904, 128, TLS1_3_VERSION, 0 },
    { 0xff06, 128, TLS1_3_VERSION, 0 },
    { 0xff07, 128, TLS1_3_VERSION, 0 },
    { 0x0905, 192, TLS1_3_VERSION, 0 },
    { 0xff08, 192, TLS1_3_VERSION, 0 },
    { 0x0906, 256, TLS1_3_VERSION, 0 },
    { 0xff09, 256, TLS1_3_VERSION, 0 },
///// OQS_TEMPLATE_FRAGMENT_SIGALG_ASSIGNMENTS_END
};

int oqs_patch_codepoints() {
    ///// OQS_TEMPLATE_FRAGMENT_CODEPOINT_PATCHING_START
   if (getenv("OQS_CODEPOINT_MLKEM512")) oqs_group_list[0].group_id = atoi(getenv("OQS_CODEPOINT_MLKEM512"));
   if (getenv("OQS_CODEPOINT_P256_MLKEM512")) oqs_group_list[1].group_id = atoi(getenv("OQS_CODEPOINT_P256_MLKEM512"));
   if (getenv("OQS_CODEPOINT_X25519_MLKEM512")) oqs_group_list[2].group_id = atoi(getenv("OQS_CODEPOINT_X25519_MLKEM512"));
   if (getenv("OQS_CODEPOINT_BP256_MLKEM512")) oqs_group_list[3].group_id = atoi(getenv("OQS_CODEPOINT_BP256_MLKEM512"));
   if (getenv("OQS_CODEPOINT_MLKEM768")) oqs_group_list[4].group_id = atoi(getenv("OQS_CODEPOINT_MLKEM768"));
   if (getenv("OQS_CODEPOINT_P384_MLKEM768")) oqs_group_list[5].group_id = atoi(getenv("OQS_CODEPOINT_P384_MLKEM768"));
   if (getenv("OQS_CODEPOINT_X448_MLKEM768")) oqs_group_list[6].group_id = atoi(getenv("OQS_CODEPOINT_X448_MLKEM768"));
   if (getenv("OQS_CODEPOINT_BP384_MLKEM768")) oqs_group_list[7].group_id = atoi(getenv("OQS_CODEPOINT_BP384_MLKEM768"));
   if (getenv("OQS_CODEPOINT_X25519MLKEM768")) oqs_group_list[8].group_id = atoi(getenv("OQS_CODEPOINT_X25519MLKEM768"));
   if (getenv("OQS_CODEPOINT_SECP256R1MLKEM768")) oqs_group_list[9].group_id = atoi(getenv("OQS_CODEPOINT_SECP256R1MLKEM768"));
   if (getenv("OQS_CODEPOINT_MLKEM1024")) oqs_group_list[10].group_id = atoi(getenv("OQS_CODEPOINT_MLKEM1024"));
   if (getenv("OQS_CODEPOINT_P521_MLKEM1024")) oqs_group_list[11].group_id = atoi(getenv("OQS_CODEPOINT_P521_MLKEM1024"));
   if (getenv("OQS_CODEPOINT_SECP384R1MLKEM1024")) oqs_group_list[12].group_id = atoi(getenv("OQS_CODEPOINT_SECP384R1MLKEM1024"));
   if (getenv("OQS_CODEPOINT_BP512_MLKEM1024")) oqs_group_list[13].group_id = atoi(getenv("OQS_CODEPOINT_BP512_MLKEM1024"));
   if (getenv("OQS_CODEPOINT_BIKEL1")) oqs_group_list[14].group_id = atoi(getenv("OQS_CODEPOINT_BIKEL1"));
   if (getenv("OQS_CODEPOINT_P256_BIKEL1")) oqs_group_list[15].group_id = atoi(getenv("OQS_CODEPOINT_P256_BIKEL1"));
   if (getenv("OQS_CODEPOINT_X25519_BIKEL1")) oqs_group_list[16].group_id = atoi(getenv("OQS_CODEPOINT_X25519_BIKEL1"));
   if (getenv("OQS_CODEPOINT_BIKEL3")) oqs_group_list[17].group_id = atoi(getenv("OQS_CODEPOINT_BIKEL3"));
   if (getenv("OQS_CODEPOINT_P384_BIKEL3")) oqs_group_list[18].group_id = atoi(getenv("OQS_CODEPOINT_P384_BIKEL3"));
   if (getenv("OQS_CODEPOINT_X448_BIKEL3")) oqs_group_list[19].group_id = atoi(getenv("OQS_CODEPOINT_X448_BIKEL3"));
   if (getenv("OQS_CODEPOINT_HQC128")) oqs_group_list[20].group_id = atoi(getenv("OQS_CODEPOINT_HQC128"));
   if (getenv("OQS_CODEPOINT_P256_HQC128")) oqs_group_list[21].group_id = atoi(getenv("OQS_CODEPOINT_P256_HQC128"));
   if (getenv("OQS_CODEPOINT_X25519_HQC128")) oqs_group_list[22].group_id = atoi(getenv("OQS_CODEPOINT_X25519_HQC128"));
   if (getenv("OQS_CODEPOINT_HQC192")) oqs_group_list[23].group_id = atoi(getenv("OQS_CODEPOINT_HQC192"));
   if (getenv("OQS_CODEPOINT_P384_HQC192")) oqs_group_list[24].group_id = atoi(getenv("OQS_CODEPOINT_P384_HQC192"));
   if (getenv("OQS_CODEPOINT_X448_HQC192")) oqs_group_list[25].group_id = atoi(getenv("OQS_CODEPOINT_X448_HQC192"));
   if (getenv("OQS_CODEPOINT_HQC256")) oqs_group_list[26].group_id = atoi(getenv("OQS_CODEPOINT_HQC256"));
   if (getenv("OQS_CODEPOINT_P521_HQC256")) oqs_group_list[27].group_id = atoi(getenv("OQS_CODEPOINT_P521_HQC256"));

   if (getenv("OQS_CODEPOINT_MLDSA44")) oqs_sigalg_list[0].code_point = atoi(getenv("OQS_CODEPOINT_MLDSA44"));
   if (getenv("OQS_CODEPOINT_P256_MLDSA44")) oqs_sigalg_list[1].code_point = atoi(getenv("OQS_CODEPOINT_P256_MLDSA44"));
   if (getenv("OQS_CODEPOINT_RSA3072_MLDSA44")) oqs_sigalg_list[2].code_point = atoi(getenv("OQS_CODEPOINT_RSA3072_MLDSA44"));
   if (getenv("OQS_CODEPOINT_MLDSA65")) oqs_sigalg_list[3].code_point = atoi(getenv("OQS_CODEPOINT_MLDSA65"));
   if (getenv("OQS_CODEPOINT_P384_MLDSA65")) oqs_sigalg_list[4].code_point = atoi(getenv("OQS_CODEPOINT_P384_MLDSA65"));
   if (getenv("OQS_CODEPOINT_MLDSA87")) oqs_sigalg_list[5].code_point = atoi(getenv("OQS_CODEPOINT_MLDSA87"));
   if (getenv("OQS_CODEPOINT_P521_MLDSA87")) oqs_sigalg_list[6].code_point = atoi(getenv("OQS_CODEPOINT_P521_MLDSA87"));
///// OQS_TEMPLATE_FRAGMENT_CODEPOINT_PATCHING_END
    return 1;
}

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg) {
    size_t i;

    for (i = 0; i < OSSL_NELEM(oqs_param_group_list); i++) {
        // do not register algorithms disabled at runtime
        if (sk_OPENSSL_STRING_find(oqsprov_get_rt_disabled_algs(),
                                   (char *)oqs_param_group_list[i][2].data) <
            0) {
            if (!cb(oqs_param_group_list[i], arg))
                return 0;
        }
    }

    return 1;
}

#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME
#define OQS_SIGALG_ENTRY(tlsname, realname, algorithm, oid, idx)               \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, #tlsname, \
                               sizeof(#tlsname)),                              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME, #tlsname,  \
                                   sizeof(#tlsname)),                          \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID, #oid,       \
                                   sizeof(#oid)),                              \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,             \
                            (unsigned int *)&oqs_sigalg_list[idx].code_point), \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,          \
                            (unsigned int *)&oqs_sigalg_list[idx].secbits),    \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,                 \
                           (unsigned int *)&oqs_sigalg_list[idx].mintls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,                 \
                           (unsigned int *)&oqs_sigalg_list[idx].maxtls),      \
            OSSL_PARAM_END                                                     \
    }

static const OSSL_PARAM oqs_param_sigalg_list[][12] = {
///// OQS_TEMPLATE_FRAGMENT_SIGALG_NAMES_START
#ifdef OQS_ENABLE_SIG_ml_dsa_44
    OQS_SIGALG_ENTRY(mldsa44, mldsa44, mldsa44, "2.16.840.1.101.3.4.3.17", 0),
    OQS_SIGALG_ENTRY(p256_mldsa44, p256_mldsa44, p256_mldsa44, "1.3.9999.7.5", 1),
    OQS_SIGALG_ENTRY(rsa3072_mldsa44, rsa3072_mldsa44, rsa3072_mldsa44, "1.3.9999.7.6", 2),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_65
    OQS_SIGALG_ENTRY(mldsa65, mldsa65, mldsa65, "2.16.840.1.101.3.4.3.18", 3),
    OQS_SIGALG_ENTRY(p384_mldsa65, p384_mldsa65, p384_mldsa65, "1.3.9999.7.7", 4),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_87
    OQS_SIGALG_ENTRY(mldsa87, mldsa87, mldsa87, "2.16.840.1.101.3.4.3.19", 5),
    OQS_SIGALG_ENTRY(p521_mldsa87, p521_mldsa87, p521_mldsa87, "1.3.9999.7.8", 6),
#endif
///// OQS_TEMPLATE_FRAGMENT_SIGALG_NAMES_END
};

static int oqs_sigalg_capability(OSSL_CALLBACK *cb, void *arg) {
    size_t i;

    // relaxed assertion for the case that not all algorithms are enabled in
    // liboqs:
    assert(OSSL_NELEM(oqs_param_sigalg_list) <= OSSL_NELEM(oqs_sigalg_list));
    for (i = 0; i < OSSL_NELEM(oqs_param_sigalg_list); i++) {
        // do not register algorithms disabled at runtime
        if (sk_OPENSSL_STRING_find(oqsprov_get_rt_disabled_algs(),
                                   (char *)oqs_param_sigalg_list[i][1].data) <
            0) {
            if (!cb(oqs_param_sigalg_list[i], arg))
                return 0;
        }
    }

    return 1;
}
#endif /* OSSL_CAPABILITY_TLS_SIGALG_NAME */

int oqs_provider_get_capabilities(void *provctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg) {
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return oqs_group_capability(cb, arg);

#ifdef OSSL_CAPABILITY_TLS_SIGALG_NAME
    if (strcasecmp(capability, "TLS-SIGALG") == 0)
        return oqs_sigalg_capability(cb, arg);
#else
#ifndef NDEBUG
    fprintf(stderr, "Warning: OSSL_CAPABILITY_TLS_SIGALG_NAME not defined: "
                    "OpenSSL version used that does not support pluggable "
                    "signature capabilities.\nUpgrading OpenSSL installation "
                    "recommended to enable QSC TLS signature support.\n\n");
#endif /* NDEBUG */
#endif /* OSSL_CAPABILITY_TLS_SIGALG_NAME */

    /* We don't support this capability */
    return 0;
}
