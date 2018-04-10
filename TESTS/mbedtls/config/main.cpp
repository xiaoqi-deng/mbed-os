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

#include <stdio.h>
#include <string.h>
#include "mbed.h"
#include "greentea-client/test_env.h"
#include "unity/unity.h"
#include "utest/utest.h"
#include "mbedtls/ssl.h"

using namespace utest::v1;



// Tests whether a generated clientHello message would contain the TLS_ECDHE_ECDSA_WITH_AES_*_GCM_SHA256 ciphersuites
#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
void test_case_ecdhe_ecdsa_with_aes_128_gcm_sha256_ciphersuite() {

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;


    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, 0);
    ssl.conf = &conf;

    const int *ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];

    int found_128 = 0;
    for( int i = 0; ciphersuites[i] != 0; i++ ) {
        if (ciphersuites[i] == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
            found_128 = 1;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_128, "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 not found in ciphersuites");
}
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
void test_case_ecdhe_ecdsa_with_aes_256_gcm_sha384_ciphersuite() {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;


    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, 0);
    ssl.conf = &conf;

    const int *ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];

    int found_256 = 0;
    for( int i = 0; ciphersuites[i] != 0; i++ ) {

        if (ciphersuites[i] == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
            found_256 = 1;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_256, "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 not found in ciphersuites");
}
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
void test_case_ecdhe_ecdsa_with_aes_128_cbc_sha256_ciphersuite() {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;


    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, 0);
    ssl.conf = &conf;

    const int *ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];

    int found_128 = 0;
    for( int i = 0; ciphersuites[i] != 0; i++ ) {
        if (ciphersuites[i] == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256) {
            found_128 = 1;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_128, "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 not found in ciphersuites");
}
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
void test_case_ecdhe_ecdsa_with_aes_256_cbc_sha384_ciphersuite() {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;


    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, 0);
    ssl.conf = &conf;

    const int *ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];

    int found_256 = 0;
    for( int i = 0; ciphersuites[i] != 0; i++ ) {
        if (ciphersuites[i] == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384) {
            found_256 = 1;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_256, "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 not found in ciphersuites");
}
#endif

#if MBED_CONF_MBEDTLS_PSK_WITH_AES_CCM_8
void test_case_psk_with_aes_ccm_8_ciphersuites() {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;


    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, 0);
    ssl.conf = &conf;

    const int *ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];

    int found_128 = 0;
    int found_256 = 0;
    for( int i = 0; ciphersuites[i] != 0; i++ ) {

        if (ciphersuites[i] == MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8) {
            found_128 = 1;
        }else if (ciphersuites[i] == MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8) {
            found_256 = 1;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_128, "PSK_WITH_AES_128_CCM_8 not found in ciphersuites");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_256, "PSK_WITH_AES_256_CCM_8 not found in ciphersuites");
}
#endif

#if MBED_CONF_MBEDTLS_PSK_WITH_AES_128_CBC_SHA256
void test_case_psk_with_aes_128_cbc_sha256_ciphersuite() {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;


    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, 0);
    ssl.conf = &conf;

    const int *ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];

    int found_128 = 0;
    for( int i = 0; ciphersuites[i] != 0; i++ ) {
        if (ciphersuites[i] == MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256) {
            found_128 = 1;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_128, "PSK_WITH_AES_128_CBC_SHA256 not found in ciphersuites");
}
#endif

#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_CCM
void test_case_ecdhe_ecdsa_with_aes_ccm_ciphersuite() {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, 0);
    ssl.conf = &conf;

    const int *ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];

    int found_norm = 0;
    int found_8 = 0;
    int found_128 = 0;
    for( int i = 0; ciphersuites[i] != 0; i++ ) {
        if (ciphersuites[i] == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM) {
            found_norm = 1;
        }
        if (ciphersuites[i] == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8) {
            found_8 = 1;
        }
        if (ciphersuites[i] == MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM) {
            found_128 = 1;
        }
    }
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_norm, "ECDHE_ECDSA_WITH_AES_256_CCM not found in ciphersuites");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_8, "ECDHE_ECDSA_WITH_AES_256_CCM_8 not found in ciphersuites");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, found_128, "ECDHE_ECDSA_WITH_AES_128_CCM not found in ciphersuites");
}
#endif

utest::v1::status_t greentea_failure_handler(const Case *const source, const failure_t reason) {
    greentea_case_failure_abort_handler(source, reason);
    return STATUS_CONTINUE;
}

Case cases[] = {
#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    Case("MbedTLS Config: ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ciphersuite", test_case_ecdhe_ecdsa_with_aes_128_gcm_sha256_ciphersuite, greentea_failure_handler),
#endif
#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    Case("MbedTLS Config: ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ciphersuite", test_case_ecdhe_ecdsa_with_aes_128_cbc_sha256_ciphersuite, greentea_failure_handler),
#endif
#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    Case("MbedTLS Config: ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ciphersuite", test_case_ecdhe_ecdsa_with_aes_256_gcm_sha384_ciphersuite, greentea_failure_handler),
#endif
#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    Case("MbedTLS Config: ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ciphersuite", test_case_ecdhe_ecdsa_with_aes_256_cbc_sha384_ciphersuite, greentea_failure_handler),
#endif
#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    Case("MbedTLS Config: ECDHE_ECDSA_WITH_AES_128_CCM_8 ciphersuite", test_case_ecdhe_ecdsa_with_aes_128_ccm_8_ciphersuite, greentea_failure_handler),
#endif
#if MBED_CONF_MBEDTLS_PSK_WITH_AES_CCM_8    
    Case("MbedTLS Config: PSK_WITH_AES_CCM_8 ciphersuites", test_case_psk_with_aes_ccm_8_ciphersuites, greentea_failure_handler),
#endif
#if MBED_CONF_MBEDTLS_PSK_WITH_AES_128_CBC_SHA256
    Case("MbedTLS Config: PSK_WITH_AES_128_CBC_SHA256 ciphersuite", test_case_psk_with_aes_128_cbc_sha256_ciphersuite, greentea_failure_handler),
#endif
#if MBED_CONF_MBEDTLS_ECDHE_ECDSA_WITH_AES_CCM
    Case("MbedTLS Config: ECDHE_ECDSA_WITH_AES_CCM ciphersuite", test_case_ecdhe_ecdsa_with_aes_ccm_ciphersuite, greentea_failure_handler),
#endif
};

utest::v1::status_t greentea_test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(10, "default_auto");
    return greentea_test_setup_handler(number_of_cases);
}

Specification specification(greentea_test_setup, cases, greentea_test_teardown_handler);

int main() {
    Harness::run(specification);
}
