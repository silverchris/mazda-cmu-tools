//
// Created by silverchris on 2022-04-23.
//

#include <cstdio>
#include <cstring>
#include <iostream>


#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, EVP_PKEY **rootkey, int bits);
int add_ext(X509 *cert, int nid, char *value);
int make_root();
int make_crl(X509_CRL **crl, EVP_PKEY **pkeyp, X509 **x509p);


int main(int argc, char **argv) {
    BIO *bio_err;


    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);


    make_root();


#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();

    BIO_free(bio_err);
    return (0);
}

int make_root() {
    X509 *x509 = nullptr;
    X509_CRL *crl = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY *rootkey = nullptr;


    mkcert(&x509, &rootkey, nullptr, 4096);

    RSA_print_fp(stdout, EVP_PKEY_get1_RSA(rootkey), 0);
    X509_print_fp(stdout, x509);

    FILE *private_key_file = fopen("jci_root_key.pem", "w");
    FILE *public_key_file = fopen("jci_root_cert.pem", "w");


    PEM_write_PrivateKey(private_key_file, rootkey, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_X509(public_key_file, x509);

    fclose(private_key_file);
    fclose(public_key_file);


    X509_free(x509);

    x509 = nullptr;
    pkey = nullptr;
    mkcert(&x509, &pkey, &rootkey, 2048);
    X509_print_fp(stdout, x509);

    private_key_file = fopen("jci_subord_key.pem", "w");
    public_key_file = fopen("jci_subord_cert.pem", "w");
    FILE *crl_file = fopen("certcrl.pem", "w");


    PEM_write_PrivateKey(private_key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_X509(public_key_file, x509);

    std::cout << make_crl(&crl, &pkey, &x509) << std::endl;
    X509_CRL_print_fp(stdout, crl);
    PEM_write_X509_CRL(crl_file, crl);

    fclose(private_key_file);
    fclose(public_key_file);
    fclose(crl_file);


    X509_free(x509);
    EVP_PKEY_free(rootkey);

    rootkey = pkey;
    x509 = nullptr;
    pkey = nullptr;

    mkcert(&x509, &pkey, &rootkey, 2048);
    X509_print_fp(stdout, x509);

    private_key_file = fopen("publisher_key.pem", "w");
    public_key_file = fopen("publisher_cert.pem", "w");

    PEM_write_PrivateKey(private_key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_X509(public_key_file, x509);

    fclose(private_key_file);
    fclose(public_key_file);


    X509_free(x509);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(rootkey);

}


int make_crl(X509_CRL **crl, EVP_PKEY **pkeyp, X509 **x509p) {
    X509V3_CTX ctx;
    X509_CRL *x = nullptr;

    if ((x = X509_CRL_new()) == nullptr)
        return 0;

    ASN1_TIME *tm = ASN1_TIME_new();

    if (tm == nullptr)
        return 0;

    if (X509_time_adj_ex(tm, 7305, 0, nullptr) == nullptr)
        return 0;


    if (!X509_CRL_set1_nextUpdate(x, tm))
        return 0;
    X509_gmtime_adj(tm, 0);
    X509_CRL_set1_lastUpdate(x, tm);

    if (!X509_CRL_set_issuer_name(x, X509_get_subject_name(*x509p)))
        return 0;

    X509_CRL_set_version(x, 1);
    X509_CRL_sign(x, *pkeyp, EVP_sha256());

    *crl = x;

}


static void callback(int p, int n, void *arg) {
    char c = 'B';

    if (p == 0) c = '.';
    if (p == 1) c = '+';
    if (p == 2) c = '*';
    if (p == 3) c = '\n';
    fputc(c, stderr);
}

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, EVP_PKEY **rootkey, int bits) {
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name;
    const unsigned char country[] = "UK";
    const unsigned char group[] = "OpenSSL Group";

    unsigned char serial[16];

    int rc = RAND_bytes(serial, sizeof(serial));

    if (rc != 1) {
        return 1;
    }


    if ((pkeyp == nullptr) || (*pkeyp == nullptr)) {
        if ((pk = EVP_PKEY_new()) == nullptr) {
            return (0);
        }
    } else
        pk = *pkeyp;

    if ((x509p == nullptr) || (*x509p == nullptr)) {
        if ((x = X509_new()) == nullptr)
            goto err;
    } else
        x = *x509p;

    rsa = RSA_generate_key(bits, RSA_F4, callback, nullptr);
    if (!EVP_PKEY_assign_RSA(pk, rsa)) {
        goto err;
    }
    rsa = nullptr;


    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), reinterpret_cast<long>(serial));
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), (long) 60 * 60 * 24 * 7305);
    X509_set_pubkey(x, pk);

    name = X509_get_subject_name(x);

    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, group, -1, -1, 0);

    /* Its self signed so set the issuer name to be the same as the
      * subject.
     */
    X509_set_issuer_name(x, name);

    /* Add various extensions: standard extensions */
    add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign, digitalSignature");

    add_ext(x, NID_subject_key_identifier, "hash");

    if (rootkey == nullptr) {
        if (!X509_sign(x, pk, EVP_sha256()))
            goto err;
    } else {
        if (!X509_sign(x, *rootkey, EVP_sha256()))
            goto err;
    }


    *x509p = x;
    *pkeyp = pk;
    return (1);
    err:
    return (0);
}

/* Add extension using V3 code: we can set the config file as nullptr
 * because we wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
    ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}


