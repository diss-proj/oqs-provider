// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider decoders
 *
 * Code strongly inspired by OpenSSL default provider.
 *
 */

#ifndef DECODER_PROVIDER
#    error Macro DECODER_PROVIDER undefined
#endif

#define DECODER_STRUCTURE_type_specific_keypair "type-specific"
#define DECODER_STRUCTURE_type_specific_params  "type-specific"
#define DECODER_STRUCTURE_type_specific         "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub  "type-specific"
#define DECODER_STRUCTURE_PKCS8                 "pkcs8"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo  "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo        "PrivateKeyInfo"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define DECODER(_name, _input, _output)                     \
    {_name, "provider=" DECODER_PROVIDER ",input=" #_input, \
     (oqs_##_input##_to_##_output##_decoder_functions)}
#define DECODER_w_structure(_name, _input, _structure, _output) \
    {_name,                                                     \
     "provider=" DECODER_PROVIDER ",input=" #_input             \
     ",structure=" DECODER_STRUCTURE_##_structure,              \
     (oqs_##_structure##_##_input##_to_##_output##_decoder_functions)}

///// OQS_TEMPLATE_FRAGMENT_MAKE_START
#ifdef OQS_KEM_ENCODERS

#ifdef OQS_ENABLE_KEM_ml_kem_512
DECODER_w_structure("mlkem512", der, PrivateKeyInfo, mlkem512),
DECODER_w_structure("mlkem512", der, SubjectPublicKeyInfo, mlkem512),
DECODER_w_structure("p256_mlkem512", der, PrivateKeyInfo, p256_mlkem512),
DECODER_w_structure("p256_mlkem512", der, SubjectPublicKeyInfo, p256_mlkem512),DECODER_w_structure("x25519_mlkem512", der, PrivateKeyInfo, x25519_mlkem512),
DECODER_w_structure("x25519_mlkem512", der, SubjectPublicKeyInfo, x25519_mlkem512),DECODER_w_structure("bp256_mlkem512", der, PrivateKeyInfo, bp256_mlkem512),
DECODER_w_structure("bp256_mlkem512", der, SubjectPublicKeyInfo, bp256_mlkem512),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
DECODER_w_structure("mlkem768", der, PrivateKeyInfo, mlkem768),
DECODER_w_structure("mlkem768", der, SubjectPublicKeyInfo, mlkem768),
DECODER_w_structure("p384_mlkem768", der, PrivateKeyInfo, p384_mlkem768),
DECODER_w_structure("p384_mlkem768", der, SubjectPublicKeyInfo, p384_mlkem768),DECODER_w_structure("x448_mlkem768", der, PrivateKeyInfo, x448_mlkem768),
DECODER_w_structure("x448_mlkem768", der, SubjectPublicKeyInfo, x448_mlkem768),DECODER_w_structure("bp384_mlkem768", der, PrivateKeyInfo, bp384_mlkem768),
DECODER_w_structure("bp384_mlkem768", der, SubjectPublicKeyInfo, bp384_mlkem768),DECODER_w_structure("X25519MLKEM768", der, PrivateKeyInfo, X25519MLKEM768),
DECODER_w_structure("X25519MLKEM768", der, SubjectPublicKeyInfo, X25519MLKEM768),DECODER_w_structure("SecP256r1MLKEM768", der, PrivateKeyInfo, SecP256r1MLKEM768),
DECODER_w_structure("SecP256r1MLKEM768", der, SubjectPublicKeyInfo, SecP256r1MLKEM768),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
DECODER_w_structure("mlkem1024", der, PrivateKeyInfo, mlkem1024),
DECODER_w_structure("mlkem1024", der, SubjectPublicKeyInfo, mlkem1024),
DECODER_w_structure("p521_mlkem1024", der, PrivateKeyInfo, p521_mlkem1024),
DECODER_w_structure("p521_mlkem1024", der, SubjectPublicKeyInfo, p521_mlkem1024),DECODER_w_structure("SecP384r1MLKEM1024", der, PrivateKeyInfo, SecP384r1MLKEM1024),
DECODER_w_structure("SecP384r1MLKEM1024", der, SubjectPublicKeyInfo, SecP384r1MLKEM1024),DECODER_w_structure("bp512_mlkem1024", der, PrivateKeyInfo, bp512_mlkem1024),
DECODER_w_structure("bp512_mlkem1024", der, SubjectPublicKeyInfo, bp512_mlkem1024),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
DECODER_w_structure("bikel1", der, PrivateKeyInfo, bikel1),
DECODER_w_structure("bikel1", der, SubjectPublicKeyInfo, bikel1),
DECODER_w_structure("p256_bikel1", der, PrivateKeyInfo, p256_bikel1),
DECODER_w_structure("p256_bikel1", der, SubjectPublicKeyInfo, p256_bikel1),DECODER_w_structure("x25519_bikel1", der, PrivateKeyInfo, x25519_bikel1),
DECODER_w_structure("x25519_bikel1", der, SubjectPublicKeyInfo, x25519_bikel1),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
DECODER_w_structure("bikel3", der, PrivateKeyInfo, bikel3),
DECODER_w_structure("bikel3", der, SubjectPublicKeyInfo, bikel3),
DECODER_w_structure("p384_bikel3", der, PrivateKeyInfo, p384_bikel3),
DECODER_w_structure("p384_bikel3", der, SubjectPublicKeyInfo, p384_bikel3),DECODER_w_structure("x448_bikel3", der, PrivateKeyInfo, x448_bikel3),
DECODER_w_structure("x448_bikel3", der, SubjectPublicKeyInfo, x448_bikel3),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
DECODER_w_structure("hqc128", der, PrivateKeyInfo, hqc128),
DECODER_w_structure("hqc128", der, SubjectPublicKeyInfo, hqc128),
DECODER_w_structure("p256_hqc128", der, PrivateKeyInfo, p256_hqc128),
DECODER_w_structure("p256_hqc128", der, SubjectPublicKeyInfo, p256_hqc128),DECODER_w_structure("x25519_hqc128", der, PrivateKeyInfo, x25519_hqc128),
DECODER_w_structure("x25519_hqc128", der, SubjectPublicKeyInfo, x25519_hqc128),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
DECODER_w_structure("hqc192", der, PrivateKeyInfo, hqc192),
DECODER_w_structure("hqc192", der, SubjectPublicKeyInfo, hqc192),
DECODER_w_structure("p384_hqc192", der, PrivateKeyInfo, p384_hqc192),
DECODER_w_structure("p384_hqc192", der, SubjectPublicKeyInfo, p384_hqc192),DECODER_w_structure("x448_hqc192", der, PrivateKeyInfo, x448_hqc192),
DECODER_w_structure("x448_hqc192", der, SubjectPublicKeyInfo, x448_hqc192),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
DECODER_w_structure("hqc256", der, PrivateKeyInfo, hqc256),
DECODER_w_structure("hqc256", der, SubjectPublicKeyInfo, hqc256),
DECODER_w_structure("p521_hqc256", der, PrivateKeyInfo, p521_hqc256),
DECODER_w_structure("p521_hqc256", der, SubjectPublicKeyInfo, p521_hqc256),
#endif

#endif /* OQS_KEM_ENCODERS */


#ifdef OQS_ENABLE_SIG_ml_dsa_44
DECODER_w_structure("mldsa44", der, PrivateKeyInfo, mldsa44),
DECODER_w_structure("mldsa44", der, SubjectPublicKeyInfo, mldsa44),DECODER_w_structure("p256_mldsa44", der, PrivateKeyInfo, p256_mldsa44),
DECODER_w_structure("p256_mldsa44", der, SubjectPublicKeyInfo, p256_mldsa44),DECODER_w_structure("rsa3072_mldsa44", der, PrivateKeyInfo, rsa3072_mldsa44),
DECODER_w_structure("rsa3072_mldsa44", der, SubjectPublicKeyInfo, rsa3072_mldsa44),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_65
DECODER_w_structure("mldsa65", der, PrivateKeyInfo, mldsa65),
DECODER_w_structure("mldsa65", der, SubjectPublicKeyInfo, mldsa65),DECODER_w_structure("p384_mldsa65", der, PrivateKeyInfo, p384_mldsa65),
DECODER_w_structure("p384_mldsa65", der, SubjectPublicKeyInfo, p384_mldsa65),
#endif
#ifdef OQS_ENABLE_SIG_ml_dsa_87
DECODER_w_structure("mldsa87", der, PrivateKeyInfo, mldsa87),
DECODER_w_structure("mldsa87", der, SubjectPublicKeyInfo, mldsa87),DECODER_w_structure("p521_mldsa87", der, PrivateKeyInfo, p521_mldsa87),
DECODER_w_structure("p521_mldsa87", der, SubjectPublicKeyInfo, p521_mldsa87),
#endif
///// OQS_TEMPLATE_FRAGMENT_MAKE_END
