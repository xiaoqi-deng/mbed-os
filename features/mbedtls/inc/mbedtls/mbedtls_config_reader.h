/*
 * Copyright (c) 2013-2018, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MBEDTLS_CONFIG_READER_H__
#define __MBEDTLS_CONFIG_READER_H__

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    #define MBEDTLS_AES_ROM_TABLES
    #define MBEDTLS_AES_C
    #define MBEDTLS_CIPHER_C
    #define MBEDTLS_SSL_CLI_C
    #define MBEDTLS_X509_USE_C

    #define MBEDTLS_SSL_TLS_C
    
    #define MBEDTLS_SHA256_C
    #define MBEDTLS_MD_C
    #define MBEDTLS_GCM_C
    #define MBEDTLS_X509_CRL_PARSE_C

    #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    #define MBEDTLS_ECDH_C
    #define MBEDTLS_ECP_C
    #define MBEDTLS_BIGNUM_C
    #define MBEDTLS_ECDSA_C
    #define MBEDTLS_X509_CRT_PARSE_C
    
    #define MBEDTLS_X509_USE_C
    
    #define MBEDTLS_OID_C
    #define MBEDTLS_PK_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_ASN1_PARSE_C

    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
    #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
    #define MBEDTLS_ECP_DP_CURVE25519_ENABLED

    #define MBEDTLS_BASE64_C
    #define MBEDTLS_PEM_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_SSL_CACHE_C
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    #define MBEDTLS_AES_ROM_TABLES
    #define MBEDTLS_AES_C
    #define MBEDTLS_CIPHER_C
    #define MBEDTLS_SSL_CLI_C
    #define MBEDTLS_X509_USE_C

    #define MBEDTLS_SSL_TLS_C
    
    #define MBEDTLS_SHA256_C
    #define MBEDTLS_MD_C
    #define MBEDTLS_CIPHER_MODE_CBC
    #define MBEDTLS_X509_CRL_PARSE_C

    #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    #define MBEDTLS_ECDH_C
    #define MBEDTLS_ECP_C
    #define MBEDTLS_BIGNUM_C
    #define MBEDTLS_ECDSA_C
    #define MBEDTLS_X509_CRT_PARSE_C
    
    #define MBEDTLS_X509_USE_C
    
    #define MBEDTLS_OID_C
    #define MBEDTLS_PK_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_ASN1_PARSE_C

    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
    #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
    #define MBEDTLS_ECP_DP_CURVE25519_ENABLED

    #define MBEDTLS_BASE64_C
    #define MBEDTLS_PEM_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_SSL_CACHE_C
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    #define MBEDTLS_AES_ROM_TABLES
    #define MBEDTLS_AES_C
    #define MBEDTLS_CIPHER_C
    #define MBEDTLS_SSL_CLI_C
    #define MBEDTLS_X509_USE_C

    #define MBEDTLS_SSL_TLS_C
    
    #define MBEDTLS_SHA512_C
    #define MBEDTLS_MD_C
    #define MBEDTLS_CIPHER_MODE_CBC
    #define MBEDTLS_X509_CRL_PARSE_C

    #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    #define MBEDTLS_ECDH_C
    #define MBEDTLS_ECP_C
    #define MBEDTLS_BIGNUM_C
    #define MBEDTLS_ECDSA_C
    #define MBEDTLS_X509_CRT_PARSE_C
    
    #define MBEDTLS_X509_USE_C
    
    #define MBEDTLS_OID_C
    #define MBEDTLS_PK_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_ASN1_PARSE_C

    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
    #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
    #define MBEDTLS_ECP_DP_CURVE25519_ENABLED

    #define MBEDTLS_BASE64_C
    #define MBEDTLS_PEM_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_SSL_CACHE_C
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
#define MBEDTLS_AES_C
    #define MBEDTLS_CIPHER_C
    #define MBEDTLS_SSL_CLI_C
    #define MBEDTLS_X509_USE_C

    #define MBEDTLS_SSL_TLS_C
    
    #define MBEDTLS_SHA384_C
    #define MBEDTLS_MD_C
    #define MBEDTLS_CCM_C
    #define MBEDTLS_X509_CRL_PARSE_C

    #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    #define MBEDTLS_ECDH_C
    #define MBEDTLS_ECP_C
    #define MBEDTLS_BIGNUM_C
    #define MBEDTLS_ECDSA_C
    #define MBEDTLS_X509_CRT_PARSE_C
    
    #define MBEDTLS_X509_USE_C
    
    #define MBEDTLS_OID_C
    #define MBEDTLS_PK_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_ASN1_PARSE_C

    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
    #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
    #define MBEDTLS_ECP_DP_CURVE25519_ENABLED

    #define MBEDTLS_BASE64_C
    #define MBEDTLS_PEM_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_SSL_CACHE_C
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    #define MBEDTLS_AES_ROM_TABLES
    #define MBEDTLS_AES_C
    #define MBEDTLS_CIPHER_C
    #define MBEDTLS_SSL_CLI_C
    #define MBEDTLS_X509_USE_C

    #define MBEDTLS_SSL_TLS_C
    
    #define MBEDTLS_SHA512_C
    #define MBEDTLS_MD_C
    #define MBEDTLS_GCM_C
    #define MBEDTLS_X509_CRL_PARSE_C

    #define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    #define MBEDTLS_ECDH_C
    #define MBEDTLS_ECP_C
    #define MBEDTLS_BIGNUM_C
    #define MBEDTLS_ECDSA_C
    #define MBEDTLS_X509_CRT_PARSE_C
    
    #define MBEDTLS_X509_USE_C
    
    #define MBEDTLS_OID_C
    #define MBEDTLS_PK_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_ASN1_PARSE_C

    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
    #define MBEDTLS_ECP_DP_SECP384R1_ENABLED
    #define MBEDTLS_ECP_DP_CURVE25519_ENABLED

    #define MBEDTLS_BASE64_C
    #define MBEDTLS_PEM_PARSE_C

    #define MBEDTLS_PK_C

    #define MBEDTLS_SSL_CACHE_C
#endif

#if MBED_CONF_MBEDTLS_PSK_WITH_AES_CCM_8
    #define MBEDTLS_CIPHER_C
    #define MBEDTLS_SSL_CLI_C

    #define MBEDTLS_SSL_TLS_C
    #define MBEDTLS_MD_C
    
    #define MBEDTLS_CCM_C
    #define MBEDTLS_AES_C

    #define MBEDTLS_SSL_CACHE_C

    #define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#endif

#if MBED_CONF_MBEDTLS_PSK_WITH_AES_128_CBC_SHA256
    #define MBEDTLS_CIPHER_C
    #define MBEDTLS_SSL_CLI_C

    #define MBEDTLS_CIPHER_MODE_CBC
    #define MBEDTLS_SSL_TLS_C
    #define MBEDTLS_MD_C
    #define MBEDTLS_AES_C

    #define MBEDTLS_SSL_CACHE_C

    #define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#endif

#include "check_config.h"

#endif // __MBEDTLS_CONFIG_READER_H__