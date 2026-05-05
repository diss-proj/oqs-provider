// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider encoders
 *
 * Code strongly inspired by OpenSSL default provider.
 *
 */

#ifndef ENCODER_PROVIDER
#    error Macro ENCODER_PROVIDER undefined
#endif

#define ENCODER_STRUCTURE_type_specific_keypair   "type-specific"
#define ENCODER_STRUCTURE_type_specific_params    "type-specific"
#define ENCODER_STRUCTURE_type_specific           "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub    "type-specific"
#define ENCODER_STRUCTURE_PKCS8                   "pkcs8"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo    "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_PrivateKeyInfo          "PrivateKeyInfo"
#define ENCODER_STRUCTURE_EncryptedPrivateKeyInfo "EncryptedPrivateKeyInfo"
#define ENCODER_STRUCTURE_PKCS1                   "pkcs1"
#define ENCODER_STRUCTURE_PKCS3                   "pkcs3"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define ENCODER_TEXT(_name, _sym)                        \
    {_name, "provider=" ENCODER_PROVIDER ",output=text", \
     (oqs_##_sym##_to_text_encoder_functions)}
#define ENCODER(_name, _sym, _fips, _output)                  \
    {_name, "provider=" ENCODER_PROVIDER ",output=" #_output, \
     (oqs_##_sym##_to_##_output##_encoder_functions)}

#define ENCODER_w_structure(_name, _sym, _output, _structure) \
    {_name,                                                   \
     "provider=" ENCODER_PROVIDER ",output=" #_output         \
     ",structure=" ENCODER_STRUCTURE_##_structure,            \
     (oqs_##_sym##_to_##_structure##_##_output##_encoder_functions)}

/*
 * Entries for human text "encoders"
 */

/*
 * Entries for key type specific output formats.  The structure name on these
 * is the same as the key type name.  This allows us to say something like:
 *
 * To replace i2d_{TYPE}PrivateKey(), i2d_{TYPE}PublicKey() and
 * i2d_{TYPE}Params(), use OSSL_ENCODER functions with an OSSL_ENCODER_CTX
 * created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", "type-specific",
 *                                   NULL, NULL);
 *
 * To replace PEM_write_bio_{TYPE}PrivateKey(), PEM_write_bio_{TYPE}PublicKey()
 * and PEM_write_bio_{TYPE}Params(), use OSSL_ENCODER functions with an
 * OSSL_ENCODER_CTX created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", "type-specific",
 *                                   NULL, NULL);
 *
 * We only implement those for which there are current i2d_ and PEM_write_bio
 * implementations.
 */

/*
 * Entries for PKCS#8 and SubjectPublicKeyInfo.
 * The "der" ones are added convenience for any user that wants to use
 * OSSL_ENCODER directly.
 * The "pem" ones also support PEM_write_bio_PrivateKey() and
 * PEM_write_bio_PUBKEY().
 */

///// OQS_TEMPLATE_FRAGMENT_MAKE_START
#ifdef OQS_KEM_ENCODERS


#ifdef OQS_ENABLE_KEM_ml_kem_512
ENCODER_w_structure("mlkem512", mlkem512, der, PrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, pem, PrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mlkem512", mlkem512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mlkem512", mlkem512),
ENCODER_w_structure("p256_mlkem512", p256_mlkem512, der, PrivateKeyInfo),
ENCODER_w_structure("p256_mlkem512", p256_mlkem512, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_mlkem512", p256_mlkem512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_mlkem512", p256_mlkem512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_mlkem512", p256_mlkem512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_mlkem512", p256_mlkem512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_mlkem512", p256_mlkem512),
ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, der, PrivateKeyInfo),
ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, pem, PrivateKeyInfo),
ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("x25519_mlkem512", x25519_mlkem512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("x25519_mlkem512", x25519_mlkem512),
ENCODER_w_structure("bp256_mlkem512", bp256_mlkem512, der, PrivateKeyInfo),
ENCODER_w_structure("bp256_mlkem512", bp256_mlkem512, pem, PrivateKeyInfo),
ENCODER_w_structure("bp256_mlkem512", bp256_mlkem512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bp256_mlkem512", bp256_mlkem512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bp256_mlkem512", bp256_mlkem512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("bp256_mlkem512", bp256_mlkem512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("bp256_mlkem512", bp256_mlkem512),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
ENCODER_w_structure("mlkem768", mlkem768, der, PrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, pem, PrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mlkem768", mlkem768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mlkem768", mlkem768),
ENCODER_w_structure("p384_mlkem768", p384_mlkem768, der, PrivateKeyInfo),
ENCODER_w_structure("p384_mlkem768", p384_mlkem768, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_mlkem768", p384_mlkem768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_mlkem768", p384_mlkem768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_mlkem768", p384_mlkem768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_mlkem768", p384_mlkem768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p384_mlkem768", p384_mlkem768),
ENCODER_w_structure("x448_mlkem768", x448_mlkem768, der, PrivateKeyInfo),
ENCODER_w_structure("x448_mlkem768", x448_mlkem768, pem, PrivateKeyInfo),
ENCODER_w_structure("x448_mlkem768", x448_mlkem768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x448_mlkem768", x448_mlkem768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x448_mlkem768", x448_mlkem768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("x448_mlkem768", x448_mlkem768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("x448_mlkem768", x448_mlkem768),
ENCODER_w_structure("bp384_mlkem768", bp384_mlkem768, der, PrivateKeyInfo),
ENCODER_w_structure("bp384_mlkem768", bp384_mlkem768, pem, PrivateKeyInfo),
ENCODER_w_structure("bp384_mlkem768", bp384_mlkem768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bp384_mlkem768", bp384_mlkem768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bp384_mlkem768", bp384_mlkem768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("bp384_mlkem768", bp384_mlkem768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("bp384_mlkem768", bp384_mlkem768),
ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, der, PrivateKeyInfo),
ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, pem, PrivateKeyInfo),
ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("X25519MLKEM768", X25519MLKEM768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("X25519MLKEM768", X25519MLKEM768),
ENCODER_w_structure("SecP256r1MLKEM768", SecP256r1MLKEM768, der, PrivateKeyInfo),
ENCODER_w_structure("SecP256r1MLKEM768", SecP256r1MLKEM768, pem, PrivateKeyInfo),
ENCODER_w_structure("SecP256r1MLKEM768", SecP256r1MLKEM768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("SecP256r1MLKEM768", SecP256r1MLKEM768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("SecP256r1MLKEM768", SecP256r1MLKEM768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("SecP256r1MLKEM768", SecP256r1MLKEM768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("SecP256r1MLKEM768", SecP256r1MLKEM768),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
ENCODER_w_structure("mlkem1024", mlkem1024, der, PrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, pem, PrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mlkem1024", mlkem1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mlkem1024", mlkem1024),
ENCODER_w_structure("p521_mlkem1024", p521_mlkem1024, der, PrivateKeyInfo),
ENCODER_w_structure("p521_mlkem1024", p521_mlkem1024, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_mlkem1024", p521_mlkem1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_mlkem1024", p521_mlkem1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_mlkem1024", p521_mlkem1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_mlkem1024", p521_mlkem1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p521_mlkem1024", p521_mlkem1024),
ENCODER_w_structure("SecP384r1MLKEM1024", SecP384r1MLKEM1024, der, PrivateKeyInfo),
ENCODER_w_structure("SecP384r1MLKEM1024", SecP384r1MLKEM1024, pem, PrivateKeyInfo),
ENCODER_w_structure("SecP384r1MLKEM1024", SecP384r1MLKEM1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("SecP384r1MLKEM1024", SecP384r1MLKEM1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("SecP384r1MLKEM1024", SecP384r1MLKEM1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("SecP384r1MLKEM1024", SecP384r1MLKEM1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("SecP384r1MLKEM1024", SecP384r1MLKEM1024),
ENCODER_w_structure("bp512_mlkem1024", bp512_mlkem1024, der, PrivateKeyInfo),
ENCODER_w_structure("bp512_mlkem1024", bp512_mlkem1024, pem, PrivateKeyInfo),
ENCODER_w_structure("bp512_mlkem1024", bp512_mlkem1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bp512_mlkem1024", bp512_mlkem1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bp512_mlkem1024", bp512_mlkem1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("bp512_mlkem1024", bp512_mlkem1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("bp512_mlkem1024", bp512_mlkem1024),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
ENCODER_w_structure("bikel1", bikel1, der, PrivateKeyInfo),
ENCODER_w_structure("bikel1", bikel1, pem, PrivateKeyInfo),
ENCODER_w_structure("bikel1", bikel1, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bikel1", bikel1, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bikel1", bikel1, der, SubjectPublicKeyInfo),
ENCODER_w_structure("bikel1", bikel1, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("bikel1", bikel1),
ENCODER_w_structure("p256_bikel1", p256_bikel1, der, PrivateKeyInfo),
ENCODER_w_structure("p256_bikel1", p256_bikel1, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_bikel1", p256_bikel1, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_bikel1", p256_bikel1, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_bikel1", p256_bikel1, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_bikel1", p256_bikel1, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_bikel1", p256_bikel1),
ENCODER_w_structure("x25519_bikel1", x25519_bikel1, der, PrivateKeyInfo),
ENCODER_w_structure("x25519_bikel1", x25519_bikel1, pem, PrivateKeyInfo),
ENCODER_w_structure("x25519_bikel1", x25519_bikel1, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x25519_bikel1", x25519_bikel1, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x25519_bikel1", x25519_bikel1, der, SubjectPublicKeyInfo),
ENCODER_w_structure("x25519_bikel1", x25519_bikel1, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("x25519_bikel1", x25519_bikel1),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
ENCODER_w_structure("bikel3", bikel3, der, PrivateKeyInfo),
ENCODER_w_structure("bikel3", bikel3, pem, PrivateKeyInfo),
ENCODER_w_structure("bikel3", bikel3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bikel3", bikel3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("bikel3", bikel3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("bikel3", bikel3, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("bikel3", bikel3),
ENCODER_w_structure("p384_bikel3", p384_bikel3, der, PrivateKeyInfo),
ENCODER_w_structure("p384_bikel3", p384_bikel3, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_bikel3", p384_bikel3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_bikel3", p384_bikel3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_bikel3", p384_bikel3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_bikel3", p384_bikel3, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p384_bikel3", p384_bikel3),
ENCODER_w_structure("x448_bikel3", x448_bikel3, der, PrivateKeyInfo),
ENCODER_w_structure("x448_bikel3", x448_bikel3, pem, PrivateKeyInfo),
ENCODER_w_structure("x448_bikel3", x448_bikel3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x448_bikel3", x448_bikel3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x448_bikel3", x448_bikel3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("x448_bikel3", x448_bikel3, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("x448_bikel3", x448_bikel3),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
ENCODER_w_structure("hqc128", hqc128, der, PrivateKeyInfo),
ENCODER_w_structure("hqc128", hqc128, pem, PrivateKeyInfo),
ENCODER_w_structure("hqc128", hqc128, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("hqc128", hqc128, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("hqc128", hqc128, der, SubjectPublicKeyInfo),
ENCODER_w_structure("hqc128", hqc128, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("hqc128", hqc128),
ENCODER_w_structure("p256_hqc128", p256_hqc128, der, PrivateKeyInfo),
ENCODER_w_structure("p256_hqc128", p256_hqc128, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_hqc128", p256_hqc128, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_hqc128", p256_hqc128, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_hqc128", p256_hqc128, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_hqc128", p256_hqc128, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_hqc128", p256_hqc128),
ENCODER_w_structure("x25519_hqc128", x25519_hqc128, der, PrivateKeyInfo),
ENCODER_w_structure("x25519_hqc128", x25519_hqc128, pem, PrivateKeyInfo),
ENCODER_w_structure("x25519_hqc128", x25519_hqc128, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x25519_hqc128", x25519_hqc128, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x25519_hqc128", x25519_hqc128, der, SubjectPublicKeyInfo),
ENCODER_w_structure("x25519_hqc128", x25519_hqc128, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("x25519_hqc128", x25519_hqc128),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
ENCODER_w_structure("hqc192", hqc192, der, PrivateKeyInfo),
ENCODER_w_structure("hqc192", hqc192, pem, PrivateKeyInfo),
ENCODER_w_structure("hqc192", hqc192, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("hqc192", hqc192, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("hqc192", hqc192, der, SubjectPublicKeyInfo),
ENCODER_w_structure("hqc192", hqc192, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("hqc192", hqc192),
ENCODER_w_structure("p384_hqc192", p384_hqc192, der, PrivateKeyInfo),
ENCODER_w_structure("p384_hqc192", p384_hqc192, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_hqc192", p384_hqc192, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_hqc192", p384_hqc192, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_hqc192", p384_hqc192, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_hqc192", p384_hqc192, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p384_hqc192", p384_hqc192),
ENCODER_w_structure("x448_hqc192", x448_hqc192, der, PrivateKeyInfo),
ENCODER_w_structure("x448_hqc192", x448_hqc192, pem, PrivateKeyInfo),
ENCODER_w_structure("x448_hqc192", x448_hqc192, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x448_hqc192", x448_hqc192, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("x448_hqc192", x448_hqc192, der, SubjectPublicKeyInfo),
ENCODER_w_structure("x448_hqc192", x448_hqc192, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("x448_hqc192", x448_hqc192),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
ENCODER_w_structure("hqc256", hqc256, der, PrivateKeyInfo),
ENCODER_w_structure("hqc256", hqc256, pem, PrivateKeyInfo),
ENCODER_w_structure("hqc256", hqc256, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("hqc256", hqc256, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("hqc256", hqc256, der, SubjectPublicKeyInfo),
ENCODER_w_structure("hqc256", hqc256, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("hqc256", hqc256),
ENCODER_w_structure("p521_hqc256", p521_hqc256, der, PrivateKeyInfo),
ENCODER_w_structure("p521_hqc256", p521_hqc256, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_hqc256", p521_hqc256, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_hqc256", p521_hqc256, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_hqc256", p521_hqc256, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_hqc256", p521_hqc256, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p521_hqc256", p521_hqc256),
#endif

#endif /* OQS_KEM_ENCODERS */


#ifdef OQS_ENABLE_SIG_ml_dsa_44
ENCODER_w_structure("mldsa44", mldsa44, der, PrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, pem, PrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mldsa44", mldsa44, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mldsa44", mldsa44),
ENCODER_w_structure("p256_mldsa44", p256_mldsa44, der, PrivateKeyInfo),
ENCODER_w_structure("p256_mldsa44", p256_mldsa44, pem, PrivateKeyInfo),
ENCODER_w_structure("p256_mldsa44", p256_mldsa44, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_mldsa44", p256_mldsa44, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p256_mldsa44", p256_mldsa44, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p256_mldsa44", p256_mldsa44, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p256_mldsa44", p256_mldsa44),
ENCODER_w_structure("rsa3072_mldsa44", rsa3072_mldsa44, der, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_mldsa44", rsa3072_mldsa44, pem, PrivateKeyInfo),
ENCODER_w_structure("rsa3072_mldsa44", rsa3072_mldsa44, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_mldsa44", rsa3072_mldsa44, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("rsa3072_mldsa44", rsa3072_mldsa44, der, SubjectPublicKeyInfo),
ENCODER_w_structure("rsa3072_mldsa44", rsa3072_mldsa44, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("rsa3072_mldsa44", rsa3072_mldsa44),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_65
ENCODER_w_structure("mldsa65", mldsa65, der, PrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, pem, PrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mldsa65", mldsa65, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mldsa65", mldsa65),
ENCODER_w_structure("p384_mldsa65", p384_mldsa65, der, PrivateKeyInfo),
ENCODER_w_structure("p384_mldsa65", p384_mldsa65, pem, PrivateKeyInfo),
ENCODER_w_structure("p384_mldsa65", p384_mldsa65, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_mldsa65", p384_mldsa65, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p384_mldsa65", p384_mldsa65, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p384_mldsa65", p384_mldsa65, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p384_mldsa65", p384_mldsa65),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_87
ENCODER_w_structure("mldsa87", mldsa87, der, PrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, pem, PrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, der, SubjectPublicKeyInfo),
ENCODER_w_structure("mldsa87", mldsa87, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("mldsa87", mldsa87),
ENCODER_w_structure("p521_mldsa87", p521_mldsa87, der, PrivateKeyInfo),
ENCODER_w_structure("p521_mldsa87", p521_mldsa87, pem, PrivateKeyInfo),
ENCODER_w_structure("p521_mldsa87", p521_mldsa87, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_mldsa87", p521_mldsa87, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("p521_mldsa87", p521_mldsa87, der, SubjectPublicKeyInfo),
ENCODER_w_structure("p521_mldsa87", p521_mldsa87, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("p521_mldsa87", p521_mldsa87),
#endif
///// OQS_TEMPLATE_FRAGMENT_MAKE_END
