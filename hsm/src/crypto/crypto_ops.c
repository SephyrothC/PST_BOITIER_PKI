/*
 * Cryptographic Operations Implementation
 * Using OpenSSL for all crypto operations
 */

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11_internal.h"
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <string.h>
#include <stdlib.h>

/*
 * Get OpenSSL curve NID from PKCS#11 EC parameters
 */
static int get_curve_nid_from_params(const uint8_t *params, size_t params_len)
{
    /* Common curves and their OID */
    /* P-256: 1.2.840.10045.3.1.7 */
    static const uint8_t p256_oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    /* P-384: 1.3.132.0.34 */
    static const uint8_t p384_oid[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
    /* P-521: 1.3.132.0.35 */
    static const uint8_t p521_oid[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

    if (params_len == sizeof(p256_oid) && memcmp(params, p256_oid, sizeof(p256_oid)) == 0) {
        return NID_X9_62_prime256v1;  /* P-256 */
    }
    if (params_len == sizeof(p384_oid) && memcmp(params, p384_oid, sizeof(p384_oid)) == 0) {
        return NID_secp384r1;  /* P-384 */
    }
    if (params_len == sizeof(p521_oid) && memcmp(params, p521_oid, sizeof(p521_oid)) == 0) {
        return NID_secp521r1;  /* P-521 */
    }

    return NID_undef;
}

/*
 * Get EC parameters (OID) from curve name
 */
static CK_RV get_ec_params_from_nid(int nid, uint8_t **params, size_t *params_len)
{
    static const uint8_t p256_oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    static const uint8_t p384_oid[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
    static const uint8_t p521_oid[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

    const uint8_t *oid = NULL;
    size_t oid_len = 0;

    switch (nid) {
        case NID_X9_62_prime256v1:
            oid = p256_oid;
            oid_len = sizeof(p256_oid);
            break;
        case NID_secp384r1:
            oid = p384_oid;
            oid_len = sizeof(p384_oid);
            break;
        case NID_secp521r1:
            oid = p521_oid;
            oid_len = sizeof(p521_oid);
            break;
        default:
            return CKR_DOMAIN_PARAMS_INVALID;
    }

    *params = malloc(oid_len);
    if (!*params) {
        return CKR_HOST_MEMORY;
    }

    memcpy(*params, oid, oid_len);
    *params_len = oid_len;

    return CKR_OK;
}

/*
 * Generate RSA key pair
 */
CK_RV hsm_generate_key_pair_rsa(CK_ULONG key_bits, hsm_object_t *pub_key, hsm_object_t *priv_key)
{
    hsm_log(HSM_LOG_INFO, "Generating RSA-%lu key pair", key_bits);

    if (key_bits != 2048 && key_bits != 4096) {
        hsm_log(HSM_LOG_ERROR, "Invalid RSA key size: %lu", key_bits);
        return CKR_KEY_SIZE_RANGE;
    }

    /* Generate RSA key */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        hsm_log(HSM_LOG_ERROR, "Failed to create EVP_PKEY_CTX");
        return CKR_FUNCTION_FAILED;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return CKR_FUNCTION_FAILED;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return CKR_FUNCTION_FAILED;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        hsm_log(HSM_LOG_ERROR, "Failed to generate RSA key");
        return CKR_FUNCTION_FAILED;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Extract RSA key components */
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

    /* Public key */
    pub_key->key_type = KEY_TYPE_RSA;
    pub_key->key_data.rsa.bits = key_bits;
    pub_key->key_data.rsa.modulus_len = BN_num_bytes(n);
    pub_key->key_data.rsa.modulus = malloc(pub_key->key_data.rsa.modulus_len);
    BN_bn2bin(n, pub_key->key_data.rsa.modulus);

    pub_key->key_data.rsa.public_exponent_len = BN_num_bytes(e);
    pub_key->key_data.rsa.public_exponent = malloc(pub_key->key_data.rsa.public_exponent_len);
    BN_bn2bin(e, pub_key->key_data.rsa.public_exponent);

    /* Private key */
    priv_key->key_type = KEY_TYPE_RSA;
    priv_key->key_data.rsa.bits = key_bits;
    priv_key->key_data.rsa.modulus_len = BN_num_bytes(n);
    priv_key->key_data.rsa.modulus = malloc(priv_key->key_data.rsa.modulus_len);
    BN_bn2bin(n, priv_key->key_data.rsa.modulus);

    priv_key->key_data.rsa.public_exponent_len = BN_num_bytes(e);
    priv_key->key_data.rsa.public_exponent = malloc(priv_key->key_data.rsa.public_exponent_len);
    BN_bn2bin(e, priv_key->key_data.rsa.public_exponent);

    priv_key->key_data.rsa.private_exponent_len = BN_num_bytes(d);
    priv_key->key_data.rsa.private_exponent = malloc(priv_key->key_data.rsa.private_exponent_len);
    BN_bn2bin(d, priv_key->key_data.rsa.private_exponent);

    priv_key->key_data.rsa.prime1_len = BN_num_bytes(p);
    priv_key->key_data.rsa.prime1 = malloc(priv_key->key_data.rsa.prime1_len);
    BN_bn2bin(p, priv_key->key_data.rsa.prime1);

    priv_key->key_data.rsa.prime2_len = BN_num_bytes(q);
    priv_key->key_data.rsa.prime2 = malloc(priv_key->key_data.rsa.prime2_len);
    BN_bn2bin(q, priv_key->key_data.rsa.prime2);

    priv_key->key_data.rsa.exponent1_len = BN_num_bytes(dmp1);
    priv_key->key_data.rsa.exponent1 = malloc(priv_key->key_data.rsa.exponent1_len);
    BN_bn2bin(dmp1, priv_key->key_data.rsa.exponent1);

    priv_key->key_data.rsa.exponent2_len = BN_num_bytes(dmq1);
    priv_key->key_data.rsa.exponent2 = malloc(priv_key->key_data.rsa.exponent2_len);
    BN_bn2bin(dmq1, priv_key->key_data.rsa.exponent2);

    priv_key->key_data.rsa.coefficient_len = BN_num_bytes(iqmp);
    priv_key->key_data.rsa.coefficient = malloc(priv_key->key_data.rsa.coefficient_len);
    BN_bn2bin(iqmp, priv_key->key_data.rsa.coefficient);

    RSA_free(rsa);
    EVP_PKEY_free(pkey);

    hsm_log(HSM_LOG_INFO, "RSA key pair generated successfully");
    return CKR_OK;
}

/*
 * Generate EC key pair
 */
CK_RV hsm_generate_key_pair_ec(int curve_nid, hsm_object_t *pub_key, hsm_object_t *priv_key)
{
    const char *curve_name = OBJ_nid2sn(curve_nid);
    hsm_log(HSM_LOG_INFO, "Generating EC key pair: curve=%s", curve_name ? curve_name : "unknown");

    if (curve_nid != NID_X9_62_prime256v1 &&
        curve_nid != NID_secp384r1 &&
        curve_nid != NID_secp521r1) {
        hsm_log(HSM_LOG_ERROR, "Unsupported EC curve");
        return CKR_DOMAIN_PARAMS_INVALID;
    }

    /* Generate EC key */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        return CKR_FUNCTION_FAILED;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return CKR_FUNCTION_FAILED;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return CKR_FUNCTION_FAILED;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        hsm_log(HSM_LOG_ERROR, "Failed to generate EC key");
        return CKR_FUNCTION_FAILED;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Extract EC key components */
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *pub_point = EC_KEY_get0_public_key(ec_key);
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(ec_key);

    /* Get EC params (curve OID) */
    uint8_t *ec_params = NULL;
    size_t ec_params_len = 0;
    CK_RV rv = get_ec_params_from_nid(curve_nid, &ec_params, &ec_params_len);
    if (rv != CKR_OK) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return rv;
    }

    /* Convert public key point to octet string */
    size_t pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    uint8_t *pub_data = malloc(pub_len);
    EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_data, pub_len, NULL);

    /* Convert private key to bytes */
    size_t priv_len = BN_num_bytes(priv_bn);
    uint8_t *priv_data = malloc(priv_len);
    BN_bn2bin(priv_bn, priv_data);

    /* Public key */
    pub_key->key_type = KEY_TYPE_EC;
    pub_key->key_data.ec.curve_nid = curve_nid;
    pub_key->key_data.ec.ec_params = ec_params;
    pub_key->key_data.ec.ec_params_len = ec_params_len;
    pub_key->key_data.ec.ec_point = pub_data;
    pub_key->key_data.ec.ec_point_len = pub_len;
    pub_key->key_data.ec.ec_private = NULL;
    pub_key->key_data.ec.ec_private_len = 0;

    /* Private key */
    priv_key->key_type = KEY_TYPE_EC;
    priv_key->key_data.ec.curve_nid = curve_nid;
    priv_key->key_data.ec.ec_params = malloc(ec_params_len);
    memcpy(priv_key->key_data.ec.ec_params, ec_params, ec_params_len);
    priv_key->key_data.ec.ec_params_len = ec_params_len;
    priv_key->key_data.ec.ec_point = malloc(pub_len);
    memcpy(priv_key->key_data.ec.ec_point, pub_data, pub_len);
    priv_key->key_data.ec.ec_point_len = pub_len;
    priv_key->key_data.ec.ec_private = priv_data;
    priv_key->key_data.ec.ec_private_len = priv_len;

    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);

    hsm_log(HSM_LOG_INFO, "EC key pair generated successfully");
    return CKR_OK;
}

/*
 * Sign data with RSA key
 */
static CK_RV sign_rsa(hsm_object_t *priv_key, CK_MECHANISM_TYPE mechanism,
                      const uint8_t *data, size_t data_len,
                      uint8_t *signature, size_t *signature_len)
{
    /* Reconstruct RSA key from components */
    RSA *rsa = RSA_new();
    if (!rsa) {
        return CKR_FUNCTION_FAILED;
    }

    BIGNUM *n = BN_bin2bn(priv_key->key_data.rsa.modulus, priv_key->key_data.rsa.modulus_len, NULL);
    BIGNUM *e = BN_bin2bn(priv_key->key_data.rsa.public_exponent, priv_key->key_data.rsa.public_exponent_len, NULL);
    BIGNUM *d = BN_bin2bn(priv_key->key_data.rsa.private_exponent, priv_key->key_data.rsa.private_exponent_len, NULL);

    RSA_set0_key(rsa, n, e, d);

    if (priv_key->key_data.rsa.prime1) {
        BIGNUM *p = BN_bin2bn(priv_key->key_data.rsa.prime1, priv_key->key_data.rsa.prime1_len, NULL);
        BIGNUM *q = BN_bin2bn(priv_key->key_data.rsa.prime2, priv_key->key_data.rsa.prime2_len, NULL);
        RSA_set0_factors(rsa, p, q);
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    /* Determine hash algorithm */
    const EVP_MD *md = NULL;
    switch (mechanism) {
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
            md = EVP_sha256();
            break;
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:
            md = EVP_sha384();
            break;
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:
            md = EVP_sha512();
            break;
        case CKM_RSA_PKCS:
            /* Raw RSA signature - data should already be hashed */
            md = NULL;
            break;
        default:
            EVP_PKEY_free(pkey);
            return CKR_MECHANISM_INVALID;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    EVP_PKEY_CTX *pctx = NULL;
    if (md) {
        if (EVP_DigestSignInit(mdctx, &pctx, md, NULL, pkey) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }
    }

    /* For PSS, set padding */
    if (mechanism == CKM_SHA256_RSA_PKCS_PSS ||
        mechanism == CKM_SHA384_RSA_PKCS_PSS ||
        mechanism == CKM_SHA512_RSA_PKCS_PSS) {
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);  /* Maximum salt length */
    }

    size_t sig_len = 0;
    if (md) {
        if (EVP_DigestSignUpdate(mdctx, data, data_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }

        if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }

        if (*signature_len < sig_len) {
            *signature_len = sig_len;
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_BUFFER_TOO_SMALL;
        }

        if (EVP_DigestSignFinal(mdctx, signature, &sig_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }
    } else {
        /* Raw RSA signature */
        int rsa_size = RSA_size(rsa);
        if (*signature_len < (size_t)rsa_size) {
            *signature_len = rsa_size;
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_BUFFER_TOO_SMALL;
        }

        int ret = RSA_private_encrypt(data_len, data, signature, rsa, RSA_PKCS1_PADDING);
        if (ret == -1) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }
        sig_len = ret;
    }

    *signature_len = sig_len;

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return CKR_OK;
}

/*
 * Sign data with EC key
 */
static CK_RV sign_ec(hsm_object_t *priv_key, CK_MECHANISM_TYPE mechanism,
                     const uint8_t *data, size_t data_len,
                     uint8_t *signature, size_t *signature_len)
{
    /* Reconstruct EC key */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(priv_key->key_data.ec.curve_nid);
    if (!ec_key) {
        return CKR_FUNCTION_FAILED;
    }

    /* Set public key point */
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    EC_POINT_oct2point(group, pub_point, priv_key->key_data.ec.ec_point,
                       priv_key->key_data.ec.ec_point_len, NULL);
    EC_KEY_set_public_key(ec_key, pub_point);
    EC_POINT_free(pub_point);

    /* Set private key */
    BIGNUM *priv_bn = BN_bin2bn(priv_key->key_data.ec.ec_private,
                                priv_key->key_data.ec.ec_private_len, NULL);
    EC_KEY_set_private_key(ec_key, priv_bn);
    BN_free(priv_bn);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    /* Determine hash algorithm */
    const EVP_MD *md = NULL;
    switch (mechanism) {
        case CKM_ECDSA_SHA256:
            md = EVP_sha256();
            break;
        case CKM_ECDSA_SHA384:
            md = EVP_sha384();
            break;
        case CKM_ECDSA_SHA512:
            md = EVP_sha512();
            break;
        case CKM_ECDSA:
            /* Raw ECDSA - data should already be hashed */
            md = NULL;
            break;
        default:
            EVP_PKEY_free(pkey);
            return CKR_MECHANISM_INVALID;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    size_t sig_len = 0;
    if (md) {
        if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }

        if (EVP_DigestSignUpdate(mdctx, data, data_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }

        if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }

        if (*signature_len < sig_len) {
            *signature_len = sig_len;
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_BUFFER_TOO_SMALL;
        }

        if (EVP_DigestSignFinal(mdctx, signature, &sig_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }
    } else {
        /* Raw ECDSA signature */
        ECDSA_SIG *sig = ECDSA_do_sign(data, data_len, ec_key);
        if (!sig) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;
        }

        int der_len = i2d_ECDSA_SIG(sig, NULL);
        if (*signature_len < (size_t)der_len) {
            *signature_len = der_len;
            ECDSA_SIG_free(sig);
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return CKR_BUFFER_TOO_SMALL;
        }

        uint8_t *sig_ptr = signature;
        der_len = i2d_ECDSA_SIG(sig, &sig_ptr);
        sig_len = der_len;

        ECDSA_SIG_free(sig);
    }

    *signature_len = sig_len;

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return CKR_OK;
}

/*
 * Sign data with private key
 */
CK_RV hsm_sign_data(hsm_object_t *priv_key, CK_MECHANISM_TYPE mechanism,
                    const uint8_t *data, size_t data_len,
                    uint8_t *signature, size_t *signature_len)
{
    if (priv_key->type != OBJ_TYPE_PRIVATE_KEY) {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (priv_key->key_type == KEY_TYPE_RSA) {
        return sign_rsa(priv_key, mechanism, data, data_len, signature, signature_len);
    } else if (priv_key->key_type == KEY_TYPE_EC) {
        return sign_ec(priv_key, mechanism, data, data_len, signature, signature_len);
    }

    return CKR_KEY_TYPE_INCONSISTENT;
}

/*
 * Verify signature (implementation similar to sign but using public key)
 */
CK_RV hsm_verify_signature(hsm_object_t *pub_key, CK_MECHANISM_TYPE mechanism,
                           const uint8_t *data, size_t data_len,
                           const uint8_t *signature, size_t signature_len)
{
    /* TODO: Implement verification - similar structure to signing */
    /* For now, return not implemented */
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * C_GenerateRandom - Generate random data
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR RandomData,
    CK_ULONG ulRandomLen)
{
    if (RandomData == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    CK_RV rv = hsm_verify_session(hSession);
    if (rv != CKR_OK) {
        return rv;
    }

    if (RAND_bytes(RandomData, ulRandomLen) != 1) {
        return CKR_RANDOM_NO_RNG;
    }

    return CKR_OK;
}
